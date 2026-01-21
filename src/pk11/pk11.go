// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package pk11 provides a wrapper over the "github.com/miekg/pkcs11" library
// that exposes a reasonably agnostic interface.
package pk11

import (
	"crypto"
	"fmt"
	"math/rand"
	"sync"
	"time"

	// Ensure the necessary hash functions are linked in.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/miekg/pkcs11"
)

// Error represents a wrapped pkcs11.Error
type Error struct {
	// The raw error code returned by the library.
	Raw pkcs11.Error
	ctx string
}

// newError wraps an error, possibly retaining information from the
// PKCS#11 library.
func newError(raw error, fmtStr string, args ...any) error {
	ctx := fmt.Sprintf(fmtStr, args...)
	if e11, ok := raw.(pkcs11.Error); ok {
		return Error{e11, ctx}
	}

	return fmt.Errorf("%s: %s", ctx, raw)
}

// Error converts this error into a user-displayable string.
func (e Error) Error() string {
	if e.ctx == "" {
		return e.Raw.Error()
	}
	return fmt.Sprintf("%s: %s", e.ctx, e.Raw)
}

// Mod wraps a context to a PKCS#11 library plugin.
//
// This type, along with Load(), is the entry-point for this library.
type Mod struct {
	ctx     *pkcs11.Ctx
	version pkcs11.Version
}

// Load loads a PKCS#11 plugin located at soPath.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func Load(soPath string) (*Mod, error) {
	ctx := pkcs11.New(soPath)
	if ctx == nil {
		return nil, fmt.Errorf("could not load module %q", soPath)
	}
	// By excluding the CKR_CRYPTOKI_ALREADY_INITIALIZED error we enable multiple sessions per module
	if err := ctx.Initialize(); err != nil && err.(pkcs11.Error) != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		return nil, newError(err, "could not initialize module %q", soPath)
	}

	info, err := ctx.GetInfo()
	if err != nil {
		return nil, newError(err, "could not retrieve module information")
	}

	return &Mod{ctx, info.CryptokiVersion}, nil
}

// Raw returns the wrapped PKCS#11 context for performing operations on directly.
//
// This function should be avoided in favor of the idiomatic interface, but is
// exposed for cases where it is absolutely unavoidable.
func (m *Mod) Raw() *pkcs11.Ctx {
	return m.ctx
}

// Tokens returns a slice containing each token the PKCS#11 module can currently
// see; PKCS#11 slots without tokens in them are inaccessible.
func (m *Mod) Tokens() ([]Token, error) {
	slots, err := m.Raw().GetSlotList( /*tokenPresent=*/ true)
	if err != nil {
		return nil, newError(err, "could not stat tokens")
	}

	var toks []Token
	for _, slot := range slots {
		toks = append(toks, Token{m, slot})
	}
	return toks, nil
}

var (
	idRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	idRandMu sync.Mutex
)

// addIDsToTemplates conditionally adds randomly-generated CKA_ID attributes to the given
// list of templates.
//
// This function is necessary since not all versions of PKCS#11 require doing this.
func (m *Mod) appendAttrKeyID(templates ...*[]*pkcs11.Attribute) {
	// Always generate a random CKA_ID.
	// Although PKCS#11 v3 says the HSM should generate it, SoftHSMv2 (even if reporting v3)
	// might not do it automatically or reliably for all key types without explicit request.
	// Providing it manually ensures we can find the key later.
	idBytes := make([]byte, 8)
	// This doesn't need to be unpredictable; it just needs to be *a* value.
	// Hence the use of fairly vanilla insecure randomness.
	idRandMu.Lock()
	id := idRand.Uint64()
	idRandMu.Unlock()

	for i := range idBytes {
		idBytes[i] = byte(id)
		id >>= 8
	}

	for _, t := range templates {
		*t = append(*t, pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes))
	}
}

// Token represents an HSM token plugged into a slot.
type Token struct {
	m    *Mod
	slot uint
}

// OpenSession opens a read-write session on a token.
func (t Token) OpenSession() (*Session, error) {
	sess, err := t.m.Raw().OpenSession(t.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, newError(err, "could not open session on slot %d", t.slot)
	}

	return &Session{t, sess}, nil
}

// UserType is a type of user that can log into a token.
type UserType int

const (
	NormalUser UserType = iota
	SecurityOfficerUser
)

// String converts a user type to a pretty-printable name.
func (u UserType) String() string {
	switch u {
	case NormalUser:
		return "normal user"
	case SecurityOfficerUser:
		return "security officer"
	default:
		return "unknown"
	}
}

// Session represents an active session on an HSM token.
//
// Sessions are needed to do anything interesting with the token, such as
// creating any kind of object or performing operations with them.
type Session struct {
	tok Token
	raw pkcs11.SessionHandle
}

// Login logs into the token this session is on.
//
// pin should be in textual form (e.g. as a hex string), rather than as an integer.
func (s *Session) Login(user UserType, pin string) error {
	var userType uint
	switch user {
	case NormalUser:
		userType = pkcs11.CKU_USER
	case SecurityOfficerUser:
		userType = pkcs11.CKU_SO
	default:
		return fmt.Errorf("unknown user type: %d", user)
	}

	// Ignore CKR_USER_ALREADY_LOGGED_IN since the system uses the same user
	// to login across parallel sessions.
	if err := s.tok.m.Raw().Login(s.raw, userType, pin); err != nil && err.(pkcs11.Error) != pkcs11.CKR_USER_ALREADY_LOGGED_IN {
		return newError(err, "could not log in as %q on slot %d", user, s.tok.slot)
	}
	return nil
}

// Logout logs out of the current session.
//
// Panics on failure, so that errors are not silently swallowed by defer.
func (s *Session) Logout() {
	if err := s.tok.m.Raw().Logout(s.raw); err != nil {
		err = newError(err, "could not log out of token in slot %d", s.tok.slot)
		panic(err)
	}
}

// DestroyKeyPairObject removes object from the current session.
func (s *Session) DestroyKeyPairObject(kp KeyPair) error {
	privateKeyObj := kp.PrivateKey
	err := s.tok.m.Raw().DestroyObject(s.raw, privateKeyObj.object.raw)
	if err != nil {
		return newError(err, "could not remove private object")
	}
	publicKeyObj := kp.PublicKey
	err = s.tok.m.Raw().DestroyObject(s.raw, publicKeyObj.object.raw)
	if err != nil {
		return newError(err, "could not remove private object")
	}
	return nil
}

// makeHash computes a hash of message.
func makeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v not available", hash)
	}

	hasher := hash.New()
	for len(message) > 0 {
		n, err := hasher.Write(message)
		if err != nil {
			return nil, fmt.Errorf("could not compute hash: %s", err)
		}
		message = message[n:]
	}

	return hasher.Sum(nil), nil
}

func ComputeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	return makeHash(hash, message)
}
