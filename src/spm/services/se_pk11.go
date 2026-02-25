// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Secure element implementation using an HSM.
package se

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
)

// sessionQueue implements a thread-safe HSM session queue. See `insert` and
// `getHandle` functions for more details.
type sessionQueue struct {
	// numSessions is the number of sessions managed by the queue.
	numSessions int

	// s is an HSM session channel.
	s chan *pk11.Session
}

// newSessionQueue creates a session queue with a channel of depth `num`.
func newSessionQueue(num int) *sessionQueue {
	return &sessionQueue{
		numSessions: num,
		s:           make(chan *pk11.Session, num),
	}
}

// insert adds a new session `s` to the session queue.
func (q *sessionQueue) insert(s *pk11.Session) error {
	// TODO: Consider adding a timeout context to avoid deadlocks if the caller
	// forgets to call the release function returned by the `getHandle`
	// function.
	if len(q.s) >= q.numSessions {
		return errors.New("Reached maximum session queue capacity.")
	}
	q.s <- s
	return nil
}

// getHandle returns a session from the queue and a release function to
// get the session back into the queue. Recommended use:
//
//	session, release := s.getHandle()
//	defer release()
//
// Note: failing to call the release function can result into deadlocks
// if the queue remains empty after calling the `insert` function.
func (q *sessionQueue) getHandle() (*pk11.Session, func()) {
	s := <-q.s
	release := func() {
		q.insert(s)
	}
	return s, release
}

// HSMConfig contains parameters used to configure a new HSM instance with the
// `NewHSM` function.
type HSMConfig struct {
	// soPath is the path to the PKCS#11 library used to connect to the HSM.
	SOPath string

	// slotID is the HSM slot ID.
	SlotID int

	// HSMPassword is the Crypto User HSM password.
	HSMPassword string

	// NumSessions configures the number of sessions to open in `SlotID`.
	NumSessions int

	// SymmetricKeys contains the list of symmetric key labels to use for
	// retrieving long-lived symmetric keys on the HSM.
	SymmetricKeys []string

	// PrivateKeys contains the list of private key labels to use for
	// retrieving long-lived private keys on the HSM.
	PrivateKeys []string

	// PublicKeys contains the list of public key labels to use for
	// retrieving long-lived public keys on the HSM.
	PublicKeys []string
}

// HSM is a wrapper over a pk11 session that conforms to the SPM interface.
type HSM struct {
	// UIDs of key objects to use for retrieving long-lived symmetric keys on
	// the HSM.
	SymmetricKeys map[string][]byte

	// UIDs of key objects to use for retrieving long-lived private keys on
	// the HSM.
	PrivateKeys map[string][]byte

	// UIDs of key objects to use for retrieving long-lived public keys on
	// the HSM.
	PublicKeys map[string][]byte

	// The PKCS#11 session we're working with.
	sessions *sessionQueue
}

// openSessions opens `numSessions` sessions on the HSM `tokSlot` slot number.
// Logs in as crypto user with `hsmPW` password. Connects via PKCS#11 shared
// library in `soPath`.
func openSessions(soPath, hsmPW string, tokSlot, numSessions int) (*sessionQueue, error) {
	mod, err := pk11.Load(soPath)
	if err != nil {
		return nil, fmt.Errorf("fail to load pk11: %v", err)
	}
	toks, err := mod.Tokens()
	if err != nil {
		return nil, fmt.Errorf("failed to open tokens: %v", err)
	}
	if tokSlot >= len(toks) {
		return nil, fmt.Errorf("fail to find slot number: %v", err)
	}

	sessions := newSessionQueue(numSessions)
	for i := 0; i < numSessions; i++ {
		s, err := toks[tokSlot].OpenSession()
		if err != nil {
			return nil, fmt.Errorf("fail to open session to HSM: %v", err)
		}

		err = s.Login(pk11.NormalUser, hsmPW)
		if err != nil {
			return nil, fmt.Errorf("fail to login into the HSM: %v", err)
		}

		err = sessions.insert(s)
		if err != nil {
			return nil, fmt.Errorf("failed to enqueue session: %v", err)
		}
	}
	return sessions, nil
}

// GetKeyIDByLabel returns the object ID from a given label
func GetKeyIDByLabel(session *pk11.Session, classKeyType pk11.ClassAttribute, label string) ([]byte, error) {
	keyObj, err := session.FindKeyByLabel(classKeyType, label)
	if err != nil {
		return nil, err
	}

	id, err := keyObj.UID()
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, fmt.Errorf("fail to find ID attribute")
	}
	return id, nil
}

// NewHSM creates a new instance of HSM, with dedicated session and keys.
func NewHSM(cfg HSMConfig) (*HSM, error) {
	sq, err := openSessions(cfg.SOPath, cfg.HSMPassword, cfg.SlotID, cfg.NumSessions)
	if err != nil {
		return nil, fmt.Errorf("fail to get session: %v", err)
	}

	hsm := &HSM{
		sessions: sq,
	}

	session, release := hsm.sessions.getHandle()
	defer release()

	hsm.SymmetricKeys = make(map[string][]byte)
	for _, key := range cfg.SymmetricKeys {
		id, err := GetKeyIDByLabel(session, pk11.ClassSecretKey, key)
		if err != nil {
			return nil, fmt.Errorf("fail to find symmetric key ID: %q, error: %v", key, err)
		}
		hsm.SymmetricKeys[key] = id
	}

	hsm.PrivateKeys = make(map[string][]byte)
	for _, key := range cfg.PrivateKeys {
		id, err := GetKeyIDByLabel(session, pk11.ClassPrivateKey, key)
		if err != nil {
			return nil, fmt.Errorf("fail to find private key ID: %q, error: %v", key, err)
		}
		hsm.PrivateKeys[key] = id
	}

	hsm.PublicKeys = make(map[string][]byte)
	for _, key := range cfg.PublicKeys {
		id, err := GetKeyIDByLabel(session, pk11.ClassPublicKey, key)
		if err != nil {
			return nil, fmt.Errorf("fail to find public key ID: %q, error: %v", key, err)
		}
		hsm.PublicKeys[key] = id
	}

	return hsm, nil
}

type CmdFunc func(*pk11.Session) error

// ExecuteCmd executes a command with a session handle in a thread safe way.
func (h *HSM) ExecuteCmd(cmd CmdFunc) error {
	session, release := h.sessions.getHandle()
	defer release()
	return cmd(session)
}

// VerifySession verifies that a session to the HSM for a given SKU is active
func (h *HSM) VerifySession() error {
	session, release := h.sessions.getHandle()
	defer release()

	kca, ok := h.PrivateKeys["KCAPriv"]
	if !ok {
		return fmt.Errorf("failed to find KCAPriv key UID")
	}

	_, err := session.FindPrivateKey(kca)
	if err != nil {
		return fmt.Errorf("failed to verify session: %v", err)
	}
	return nil
}

func (h *HSM) GenerateTokens(params []*TokenParams) ([]TokenResult, error) {
	session, release := h.sessions.getHandle()
	defer release()

	Tokens := []TokenResult{}
	for _, p := range params {
		// Only support extracting random seeds using a wrapping key.
		if p.Type != TokenTypeKeyGen && p.Wrap != WrappingMechanismNone {
			return nil, fmt.Errorf("unsupported key type %v and wrap %v", p.Type, p.Wrap)
		}

		// Select the seed asset to use (High or Low security seed).
		var seed pk11.SecretKey
		var err error
		switch p.Type {
		case TokenTypeSecurityHi:
			khs, ok := h.SymmetricKeys[p.SeedLabel]
			if !ok {
				return nil, fmt.Errorf("failed to find %q key UID", p.SeedLabel)
			}
			seed, err = session.FindSecretKey(khs)
			if err != nil {
				return nil, fmt.Errorf("failed to get KHsks key object: %v", err)
			}
		case TokenTypeSecurityLo:
			kls, ok := h.SymmetricKeys[p.SeedLabel]
			if !ok {
				return nil, fmt.Errorf("failed to find %q key UID", p.SeedLabel)
			}
			seed, err = session.FindSecretKey(kls)
			if err != nil {
				return nil, fmt.Errorf("failed to get KLsks key object: %v", err)
			}
		case TokenTypeKeyGen:
			seed, err = session.Generate(
				256,
				&pk11.KeyOptions{
					Extractable: true,
					Sensitive:   true,
					Token:       false,
				})
			if err != nil {
				return nil, fmt.Errorf("failed to generate random key: %v", err)
			}
			cleanup_seed := func() {
				if err := seed.Destroy(); err != nil {
					log.Printf("failed to destroy generated key: %v", err)
				}
			}
			defer cleanup_seed()
		default:
			return nil, fmt.Errorf("unsupported key type: %v", p.Type)
		}

		if len(p.Diversifier) == 0 {
			return nil, fmt.Errorf("invalid diversifier length: %d, expected > 0", len(p.Diversifier))
		}

		// Generate token from seed and extract.
		tBytes, err := seed.SignHMAC256(p.Diversifier)
		if err != nil {
			return nil, fmt.Errorf("failed to hash seed: %v", err)
		}

		// Truncate token if size is 128-bits (only valid value < 256 bits).
		if p.SizeInBits == 128 {
			tBytes = tBytes[:16]
		}

		if p.Op == TokenOpHashedOtLcToken {
			// OpenTitan lifecycle tokens are stored in OTP in hashed form using the
			// cSHAKE128 algorithm with the "LC_CTRL" customization string.
			hasher := sha3.NewCShake128([]byte(""), []byte("LC_CTRL"))
			hasher.Write(tBytes)
			hasher.Read(tBytes)
		}

		wkey := []byte{}
		if p.Wrap == WrappingMechanismRSAPCKS || p.Wrap == WrappingMechanismRSAOAEP {
			wk, ok := h.PublicKeys[p.WrapKeyLabel]
			if !ok {
				return nil, fmt.Errorf("failed to find %q key UID", p.WrapKeyLabel)
			}
			wkObj, err := session.FindPublicKey(wk)
			if err != nil {
				return nil, fmt.Errorf("failed to find %q key object: %v", p.WrapKeyLabel, err)
			}

			var m pk11.GenSecretWrapMechanism
			switch p.Wrap {
			case WrappingMechanismRSAPCKS:
				m = pk11.GenSecretWrapMechanismRsaPcks
			case WrappingMechanismRSAOAEP:
				m = pk11.GenSecretWrapMechanismRsaOaep
			default:
				return nil, fmt.Errorf("unsupported wrap mechanism: %v", p.Wrap)
			}
			wkey, err = seed.Wrap(wkObj, m)
			if err != nil {
				return nil, fmt.Errorf("failed to wrap seed: %v", err)
			}
		}

		Tokens = append(Tokens, TokenResult{
			Token:       tBytes,
			WrappedKey:  wkey,
			Diversifier: p.Diversifier,
		})
	}

	return Tokens, nil
}

// OIDs for ECDSA signature algorithms corresponding to SHA-256, SHA-384 and
// SHA-512.
//
// See https://datatracker.ietf.org/doc/html/rfc5758#section-3.1. The following
// text is copied from the spec for reference:
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//   us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }

// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//   us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }

// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//
//	us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// NIST FIPS 204 OIDs for ML-DSA
	oidMldsa44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMldsa65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMldsa87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// oidFromSignatureAlgorithm returns the ASN.1 object identifier for the given
// signature algorithm.
func oidFromSignatureAlgorithm(alg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch alg {
	case x509.ECDSAWithSHA256:
		return oidECDSAWithSHA256, nil
	case x509.ECDSAWithSHA384:
		return oidECDSAWithSHA384, nil
	case x509.ECDSAWithSHA512:
		return oidECDSAWithSHA512, nil
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %v", alg)
	}
}

func oidFromMLDSAParameterSet(params MldsaParameterSet) (asn1.ObjectIdentifier, error) {
	switch params {
	case MldsaParameterSet44:
		return oidMldsa44, nil
	case MldsaParameterSet65:
		return oidMldsa65, nil
	case MldsaParameterSet87:
		return oidMldsa87, nil
	default:
		return nil, fmt.Errorf("unsupported MLDSA parameter set: %v", params)
	}
}

// hashFromSignatureAlgorithm returns the crypto.Hash for the given signature
// algorithm.
func hashFromSignatureAlgorithm(alg x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch alg {
	case x509.ECDSAWithSHA256:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported signature algorithm: %v", alg)
	}
}

func (h *HSM) EndorseCert(tbs []byte, params EndorseCertParams) ([]byte, error) {
	session, release := h.sessions.getHandle()
	defer release()

	keyID, err := GetKeyIDByLabel(session, pk11.ClassPrivateKey, params.KeyLabel)
	if err != nil {
		return nil, fmt.Errorf("fail to find key with label: %q, error: %v", params.KeyLabel, err)
	}

	key, err := session.FindPrivateKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to find key object %q: %v", keyID, err)
	}

	var sigBytes []byte
	var sigType asn1.ObjectIdentifier

	if params.SignatureAlgorithm != nil {
		// ECDSA Signing
		hash, err := hashFromSignatureAlgorithm(*params.SignatureAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to get hash from signature algorithm: %v", err)
		}

		rb, sb, err := key.SignECDSA(hash, tbs)
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %v", err)
		}

		// Encode the signature as ASN.1 DER.
		var sig struct{ R, S *big.Int }
		sig.R, sig.S = new(big.Int), new(big.Int)
		sig.R.SetBytes(rb)
		sig.S.SetBytes(sb)
		sigBytes, err = asn1.Marshal(sig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal signature: %v", err)
		}

		sigType, err = oidFromSignatureAlgorithm(*params.SignatureAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to get signature algorithm OID: %v", err)
		}
	} else if params.MldsaAlgorithm != nil {
		// MLDSA Signing
		sigBytes, err = key.SignMLDSA(tbs)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with MLDSA: %v", err)
		}

		sigType, err = oidFromMLDSAParameterSet(params.MldsaAlgorithm.ParameterSets)
		if err != nil {
			return nil, fmt.Errorf("failed to get signature algorithm OID: %v", err)
		}
	} else {
		return nil, fmt.Errorf("no signature algorithm specified")
	}

	certRaw := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigType},
		SignatureValue:     asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8},
	}
	cert, err := asn1.Marshal(certRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate: %v", err)
	}

	// Verify the certificate chain.
	certObj, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	certObj.UnhandledCriticalExtensions = nil

	// Only verify if not MLDSA, as crypto/x509 does not support MLDSA verification.
	if params.MldsaAlgorithm == nil {
		roots := x509.NewCertPool()
		for _, ca := range params.Roots {
			roots.AddCert(ca)
		}
		intermediates := x509.NewCertPool()
		for _, ca := range params.Intermediates {
			intermediates.AddCert(ca)
		}
		_, err = certObj.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
		}
	}
	return cert, nil
}

func (h *HSM) EndorseData(data []byte, params EndorseCertParams) ([]byte, []byte, error) {
	session, release := h.sessions.getHandle()
	defer release()

	// Get the PKCS#11 private key object.
	keyID, err := GetKeyIDByLabel(session, pk11.ClassPrivateKey, params.KeyLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to find key with label: %q, error: %v", params.KeyLabel, err)
	}
	privateKey, err := session.FindPrivateKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find private key object %q: %v", keyID, err)
	}

	if params.SignatureAlgorithm != nil {
		// Export the public key from the PKCS#11 private key object.
		publicKeyHandle, err := privateKey.FindPublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find public key on SE: %v", err)
		}
		publicKey, err := publicKeyHandle.ExportKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to export public key from SE: %v", err)
		}
		asn1EcdsaPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %v", err)
		}

		// Hash the data payload.
		hash, err := hashFromSignatureAlgorithm(*params.SignatureAlgorithm)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get hash from signature algorithm: %v", err)
		}

		// Sign the hash of the data payload.
		rb, sb, err := privateKey.SignECDSA(hash, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign: %v", err)
		}

		// Encode the signature as ASN.1 DER.
		var sig struct{ R, S *big.Int }
		sig.R, sig.S = new(big.Int), new(big.Int)
		sig.R.SetBytes(rb)
		sig.S.SetBytes(sb)
		asn1Sig, err := asn1.Marshal(sig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal signature: %v", err)
		}

		return asn1EcdsaPublicKey, asn1Sig, nil
	} else if params.MldsaAlgorithm != nil {
		// MLDSA Signing
		sigBytes, err := privateKey.SignMLDSA(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to sign with MLDSA: %v", err)
		}
		return nil, sigBytes, nil
	} else {
		return nil, nil, fmt.Errorf("no signature algorithm specified")
	}
}

func (h *HSM) VerifyMLDSASignature(keyLabel string, data, signature []byte) error {
	session, release := h.sessions.getHandle()
	defer release()

	keyID, err := GetKeyIDByLabel(session, pk11.ClassPrivateKey, keyLabel)
	if err != nil {
		return fmt.Errorf("fail to find key with label: %q, error: %v", keyLabel, err)
	}

	privKey, err := session.FindPrivateKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to find key object %q: %v", keyID, err)
	}

	pubKey, err := privKey.FindPublicKey()
	if err != nil {
		return fmt.Errorf("failed to find public key for %q: %v", keyLabel, err)
	}

	return pubKey.VerifyMLDSA(data, signature)
}

func (h *HSM) VerifyWASSignature(params VerifyWASParams) error {
	session, release := h.sessions.getHandle()
	defer release()

	wsUID, ok := h.SymmetricKeys[params.Seed]
	if !ok {
		return fmt.Errorf("failed to find %q key UID", params.Seed)
	}
	ws, err := session.FindSecretKey(wsUID)
	if err != nil {
		return fmt.Errorf("failed to find %q key object: %v", params.Seed, err)
	}

	if len(params.Diversifier) == 0 {
		return fmt.Errorf("invalid diversifier length: %d, expected > 0", len(params.Diversifier))
	}

	was, err := ws.SignHMAC256(params.Diversifier)
	if err != nil {
		return fmt.Errorf("failed to hash seed: %v", err)
	}

	// The WAS key is loaded into the HMAC peripheral on the device as an array
	// of 32-bit words. On a little-endian system, this causes the bytes within
	// each word to be swapped. We must perform the same transformation on the
	// key before using it in Go's HMAC implementation.
	for i := 0; i < len(was); i += 4 {
		was[i], was[i+1], was[i+2], was[i+3] = was[i+3], was[i+2], was[i+1], was[i]
	}

	mac := hmac.New(sha256.New, was)
	mac.Write(params.Data)
	sig := mac.Sum(nil)

	if !hmac.Equal(sig, params.Signature) {
		log.Printf("SE.VerifyWASSignature: WAS signature check failed")
		if params.LogOnly {
			log.Printf("SE.VerifyWASSignature: WAS signature check failed (expected/got): \n%x,\n%x", params.Signature, sig)
			return nil
		}
		return fmt.Errorf("failed to verify signature (expected/got): \n%x,\n%x", params.Signature, sig)
	}
	return nil
}
