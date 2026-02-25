// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"io"

	"github.com/miekg/pkcs11"
)

// TODO: Replace with official PKCS#11 constants when available.
const (
	CKM_MLDSA              = 0x1D
	CKK_MLDSA              = 0x4A
	CKM_MLDSA_KEY_PAIR_GEN = 0x1C
)

// MldsaParameterSet specifies the ML-DSA parameter set.
type MldsaParameterSet int

const (
	MldsaParameterSetUnspecified MldsaParameterSet = 0
	MldsaParameterSet44          MldsaParameterSet = 1
	MldsaParameterSet65          MldsaParameterSet = 2
	MldsaParameterSet87          MldsaParameterSet = 3
)

// GenerateMLDSA generates an MLDSA key pair.
func (s *Session) GenerateMLDSA(params MldsaParameterSet, opts *KeyOptions) (KeyPair, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	mech := pkcs11.NewMechanism(CKM_MLDSA_KEY_PAIR_GEN, nil)

	// CKA_PARAMETER_SET is 0x61D
	const CKA_PARAMETER_SET = 0x61D

	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_PARAMETER_SET, uint(params)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_MLDSA),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}
	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_MLDSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, opts.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}

	s.tok.m.appendAttrKeyID(&pubTpl, &privTpl)

	kpu, kpr, err := s.tok.m.Raw().GenerateKeyPair(
		s.raw,
		[]*pkcs11.Mechanism{mech},
		pubTpl,
		privTpl,
	)
	if err != nil {
		return KeyPair{}, newError(err, "could not generate keys")
	}

	return KeyPair{PublicKey{object{s, kpu}}, PrivateKey{object{s, kpr}}}, nil
}

// SignMLDSA signs a message using MLDSA.
func (k PrivateKey) SignMLDSA(message []byte) ([]byte, error) {
	// Some PKCS#11 implementations might require a non-NULL parameter pointer even if length is 0.
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_MLDSA, make([]byte, 0))}
	if err := k.sess.tok.m.Raw().SignInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, newError(err, "could not begin signing operation")
	}

	data, err := k.sess.tok.m.Raw().Sign(k.sess.raw, message)
	if err != nil {
		return nil, newError(err, "could not complete signing operation")
	}
	return data, nil
}

// VerifyMLDSA verifies an MLDSA signature.
func (k PublicKey) VerifyMLDSA(message, signature []byte) error {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_MLDSA, make([]byte, 0))}
	if err := k.sess.tok.m.Raw().VerifyInit(k.sess.raw, mech, k.raw); err != nil {
		return newError(err, "could not begin verification operation")
	}

	if err := k.sess.tok.m.Raw().Verify(k.sess.raw, message, signature); err != nil {
		return newError(err, "signature verification failed")
	}
	return nil
}

// MLDSASigner implements crypto.Signer for MLDSA.
type MLDSASigner struct {
	PrivateKey
}

func (s MLDSASigner) Public() crypto.PublicKey {
	// TODO: Implement public key retrieval.
	return nil
}

func (s MLDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.PrivateKey.SignMLDSA(digest)
}
