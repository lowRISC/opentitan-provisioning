// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Secure element implementation using an HSM.
package se

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/cert/signer"
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

	// KGName is the KG key label used to find the key in the HSM.
	KGName string

	// KcaName is the KCA key label used to find the key in the HSM.
	KcaName string

	// KHsksName is the HighSecKdfSeed key label used to find the key in the HSM.
	KHsksName string

	// KLsksName is the LowSecKdfSeed key label used to find the key in the HSM.
	KLsksName string

	// hsmType contains the type of the HSM (SoftHSM or NetworkHSM)
	HSMType pk11.HSMType
}

// HSM is a wrapper over a pk11 session that conforms to the SPM interface.
type HSM struct {
	// UIDs of key objects to use for retrieving long-lived keys on the HSM.
	//
	// KG and KT are their names in the flows specification: they correspond to the
	// product revision-wide global secret (KG) and the static transport key used
	// to derive per-device transport keys (KT).
	//
	// May be nil if those keys are not present and not used by any of the called
	// methods.
	KG, KT, Kca, KHsks, KLsks []byte

	// The PKCS#11 session we're working with.
	sessions *sessionQueue
}

// openSessions opens `numSessions` sessions on the HSM `tokSlot` slot number.
// Logs in as crypto user with `hsmPW` password. Connects via PKCS#11 shared
// library in `soPath`.
func openSessions(hsmType pk11.HSMType, soPath, hsmPW string, tokSlot, numSessions int) (*sessionQueue, error) {
	mod, err := pk11.Load(hsmType, soPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fail to load pk11: %v", err)
	}
	toks, err := mod.Tokens()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open tokens: %v", err)
	}
	if tokSlot >= len(toks) {
		return nil, status.Errorf(codes.Internal, "fail to find slot number: %v", err)
	}

	sessions := newSessionQueue(numSessions)
	for i := 0; i < numSessions; i++ {
		s, err := toks[tokSlot].OpenSession()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to open session to HSM: %v", err)
		}

		err = s.Login(pk11.NormalUser, hsmPW)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to login into the HSM: %v", err)
		}

		err = sessions.insert(s)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to enqueue session: %v", err)
		}
	}
	return sessions, nil
}

// NewHSM creates a new instance of HSM, with dedicated session and keys.
func NewHSM(cfg HSMConfig) (*HSM, error) {
	sq, err := openSessions(cfg.HSMType, cfg.SOPath, cfg.HSMPassword, cfg.SlotID, cfg.NumSessions)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fail to get session: %v", err)
	}

	hsm := &HSM{
		sessions: sq,
	}

	session, release := hsm.sessions.getHandle()
	defer release()

	if cfg.KcaName != "" {
		hsm.Kca, err = hsm.getKeyIDByLabel(session, pk11.ClassPrivateKey, cfg.KcaName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to find Kca key ID: %q, error: %v", cfg.KcaName, err)
		}
	}
	if cfg.KGName != "" {
		hsm.KG, err = hsm.getKeyIDByLabel(session, pk11.ClassSecretKey, cfg.KGName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to find KG key ID: %q, error: %v", cfg.KGName, err)
		}
	}
	if cfg.KHsksName != "" {
		hsm.KHsks, err = hsm.getKeyIDByLabel(session, pk11.ClassSecretKey, cfg.KHsksName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to find KHsks key ID: %q, error: %v", cfg.KHsksName, err)
		}
	}
	if cfg.KLsksName != "" {
		hsm.KLsks, err = hsm.getKeyIDByLabel(session, pk11.ClassSecretKey, cfg.KLsksName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fail to find KLsks key ID: %q, error: %v", cfg.KLsksName, err)
		}
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

// The label used for expanding the transport secret.
var transportKeyLabel = []byte("transport key")

// deriveTransportSecret derives the transport secret for the device with the
// given ID, and returns a handle to it.
func (h *HSM) deriveTransportSecret(session *pk11.Session, deviceId []byte) (pk11.SecretKey, error) {
	transportStatic, err := session.FindSecretKey(h.KT)
	if err != nil {
		return pk11.SecretKey{}, err
	}
	return transportStatic.HKDFDeriveAES(crypto.SHA256, deviceId, transportKeyLabel, 128, &pk11.KeyOptions{Extractable: true})
}

// DeriveAndWrapTransportSecret generates a fresh secret for the device with the
// given ID, wrapping it with the global secret.
//
// See SPM.
func (h *HSM) DeriveAndWrapTransportSecret(deviceId []byte) ([]byte, error) {
	session, release := h.sessions.getHandle()
	defer release()

	global, err := session.FindSecretKey(h.KG)
	if err != nil {
		return nil, err
	}

	transport, err := h.deriveTransportSecret(session, deviceId)
	if err != nil {
		return nil, err
	}

	ciphertext, _, err := global.WrapAES(transport)
	return ciphertext, err
}

// getKeyIDByLabel returns the object ID from a given label
func (h *HSM) getKeyIDByLabel(session *pk11.Session, classKeyType pk11.ClassAttribute, label string) ([]byte, error) {
	keyObj, err := session.FindKeyByLabel(classKeyType, label)
	if err != nil {
		return nil, err
	}

	id, err := keyObj.UID()
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, status.Errorf(codes.Internal, "fail to find ID attribute")
	}
	return id, nil
}

// VerifySession verifies that a session to the HSM for a given SKU is active
func (h *HSM) VerifySession() error {
	session, release := h.sessions.getHandle()
	defer release()
	_, err := session.FindPrivateKey(h.Kca)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to verify session: %v", err)
	}
	return nil
}

// GenerateRandom returns random data extracted from the HSM.
func (h *HSM) GenerateRandom(length int) ([]byte, error) {
	session, release := h.sessions.getHandle()
	defer release()
	return session.GenerateRandom(length)
}

// GenerateKeyPairAndCert generates certificate and the associated key pair;
// must be one of RSAParams or elliptic.Curve.
func (h *HSM) GenerateKeyPairAndCert(caCert *x509.Certificate, params []SigningParams) ([]CertInfo, error) {
	session, release := h.sessions.getHandle()
	defer release()

	caObj, err := session.FindPrivateKey(h.Kca)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find Kca key object: %v", err)
	}

	ca, err := caObj.Signer()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get Kca signer: %v", err)
	}

	wi, err := session.FindSecretKey(h.KG)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get KG key object: %v", err)
	}

	certs := []CertInfo{}
	for _, p := range params {
		var kp pk11.KeyPair
		switch k := p.KeyParams.(type) {
		case RSAParams:
			kp, err = session.GenerateRSA(uint(k.ModBits), uint(k.Exp), &pk11.KeyOptions{Extractable: true})
			if err != nil {
				return nil, fmt.Errorf("failed GenerateRSA: %v", err)
			}
		case elliptic.Curve:
			kp, err = session.GenerateECDSA(k, &pk11.KeyOptions{Extractable: true})
			if err != nil {
				return nil, fmt.Errorf("failed GenerateECDSA: %v", err)
			}
		default:
			panic(fmt.Sprintf("unknown key param type: %s", reflect.TypeOf(p)))
		}

		var public any
		public, err = kp.PublicKey.ExportKey()
		if err != nil {
			return nil, fmt.Errorf("failed to export kp public key: %v", err)
		}

		var cert CertInfo
		cert.WrappedKey, cert.Iv, err = wi.WrapAES(kp.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap kp with wi: %v", err)
		}
		cert.Cert, err = signer.CreateCertificate(p.Template, caCert, public, ca)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %v", err)
		}
		certs = append(certs, cert)

		// Delete the keys after they are used once
		session.DestroyKeyPairObject(kp)
	}

	return certs, nil
}

// GenerateSymmetricKeys generates a symmetric key.
func (h *HSM) GenerateSymmetricKeys(params []*SymmetricKeygenParams) ([][]byte, error) {
	session, release := h.sessions.getHandle()
	defer release()
	var symmetricKeys [][]byte

	for _, p := range params {
		// Select the seed asset to use (High or Low security seed).
		var seed pk11.SecretKey
		var err error
		if p.UseHighSecuritySeed {
			seed, err = session.FindSecretKey(h.KHsks)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to get KHsks key object: %v", err)
			}
		} else {
			seed, err = session.FindSecretKey(h.KLsks)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to get KLsks key object: %v", err)
			}
		}

		// Generate key from seed and extract.
		seKey, err := seed.HKDFDeriveAES(crypto.SHA256, []byte(p.Sku),
			[]byte(p.Diversifier), p.SizeInBits, &pk11.KeyOptions{Extractable: true})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed HKDFDeriveAES: %v", err)
		}

		// Extract the key from the SE.
		exportedKey, err := seKey.ExportKey()
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"failed to extract symmetric key: %v", err)
		}

		// Parse and format the key bytes.
		aesKey, ok := exportedKey.(pk11.AESKey)
		if !ok {
			return nil, status.Errorf(codes.Internal,
				"failed to parse extracted symmetric key: %v", ok)
		}
		keyBytes := []byte(aesKey)
		// TODO: format it based on type (i.e. LC token or RAW)
		symmetricKeys = append(symmetricKeys, keyBytes)
	}

	return symmetricKeys, nil
}
