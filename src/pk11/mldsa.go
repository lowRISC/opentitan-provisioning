// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.2 constants for ML-DSA (FIPS 204).
// These match the OASIS PKCS#11 v3.2 specification and upstream SoftHSMv2.
const (
	CKA_PARAMETER_SET       = 0x61D
	CKK_ML_DSA              = 0x4A
	CKM_ML_DSA_KEY_PAIR_GEN = 0x1C
	CKM_ML_DSA              = 0x1D
	CKM_HASH_ML_DSA         = 0x1F

	CKP_ML_DSA_44 = 1
	CKP_ML_DSA_65 = 2
	CKP_ML_DSA_87 = 3

	// Legacy aliases for backwards compatibility.
	CKM_MLDSA              = CKM_ML_DSA
	CKK_MLDSA              = CKK_ML_DSA
	CKM_MLDSA_KEY_PAIR_GEN = CKM_ML_DSA_KEY_PAIR_GEN
)

// MldsaParameterSet specifies the ML-DSA parameter set.
type MldsaParameterSet int

const (
	MldsaParameterSetUnspecified MldsaParameterSet = 0
	MldsaParameterSet44          MldsaParameterSet = CKP_ML_DSA_44
	MldsaParameterSet65          MldsaParameterSet = CKP_ML_DSA_65
	MldsaParameterSet87          MldsaParameterSet = CKP_ML_DSA_87
)

// GenerateMLDSA generates an MLDSA key pair.
func (s *Session) GenerateMLDSA(params MldsaParameterSet, opts *KeyOptions) (KeyPair, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	mech := pkcs11.NewMechanism(CKM_ML_DSA_KEY_PAIR_GEN, nil)

	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_PARAMETER_SET, uint(params)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_ML_DSA),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}
	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_ML_DSA),
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
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_ML_DSA, make([]byte, 0))}
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
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_ML_DSA, make([]byte, 0))}
	if err := k.sess.tok.m.Raw().VerifyInit(k.sess.raw, mech, k.raw); err != nil {
		return newError(err, "could not begin verification operation")
	}

	if err := k.sess.tok.m.Raw().Verify(k.sess.raw, message, signature); err != nil {
		return newError(err, "signature verification failed")
	}
	return nil
}

// exportMLDSAPublic exports an ML-DSA public key from the HSM as *mldsa.PublicKey.
func (k PublicKey) exportMLDSAPublic() (*mldsa.PublicKey, error) {
	paramSet, err := k.Int(CKA_PARAMETER_SET)
	if err != nil {
		return nil, newError(err, "could not get CKA_PARAMETER_SET")
	}

	val, err := k.Attr(pkcs11.CKA_VALUE)
	if err != nil {
		return nil, newError(err, "could not get CKA_VALUE")
	}

	var params mldsa.Parameters
	switch paramSet {
	case CKP_ML_DSA_44:
		params = mldsa.MLDSA44()
	case CKP_ML_DSA_65:
		params = mldsa.MLDSA65()
	case CKP_ML_DSA_87:
		params = mldsa.MLDSA87()
	default:
		return nil, fmt.Errorf("unsupported MLDSA parameter set: %d", paramSet)
	}

	pub, err := mldsa.NewPublicKey(params, val)
	if err != nil {
		return nil, fmt.Errorf("could not parse MLDSA public key: %w", err)
	}
	return pub, nil
}

// MLDSASigner is a crypto.Signer backed by a PrivateKey.
type MLDSASigner struct {
	// The public key, which may not actually live on the device itself.
	*mldsa.PublicKey
	// The private key, which is stored on-device.
	PrivateKey
}

// NewMLDSASigner creates a new signer by looking up the corresponding public
// key on the HSM and exporting it.
func NewMLDSASigner(k PrivateKey) (MLDSASigner, error) {
	pub, err := k.FindPublicKey()
	if err != nil {
		return MLDSASigner{}, err
	}
	export, err := pub.ExportKey()
	if err != nil {
		return MLDSASigner{}, err
	}
	mldsaPub, ok := export.(*mldsa.PublicKey)
	if !ok {
		return MLDSASigner{}, fmt.Errorf("expected *mldsa.PublicKey, got something else: %T", export)
	}

	return MLDSASigner{mldsaPub, k}, nil
}

// Public returns the public key.
//
// This is part of interface crypto.Signer.
func (s MLDSASigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs message with the signer's private key.
//
// The HSM provides randomness, so the randomness source parameter is ignored (and may even be nil!).
//
// This is part of interface crypto.Signer.
func (s MLDSASigner) Sign(ignored io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.PrivateKey.SignMLDSA(message)
}
