// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// GenericSecretKey is a generic secret key on the Go side.
type GenericSecretKey []byte

// Generates a generic secret key of the given length. The key can be used for
// key derivation.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (s *Session) Generate(keyBitLen uint, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	if keyBitLen%8 != 0 || keyBitLen < 128 {
		return SecretKey{}, fmt.Errorf("keyBitLen must be a multiple of 8 >= 128; got %d", keyBitLen)
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_GENERIC_SECRET_KEY_GEN, nil)

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBitLen/8),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, opts.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}
	s.tok.m.appendAttrKeyID(&tpl)

	k, err := s.tok.m.Raw().GenerateKey(
		s.raw,
		[]*pkcs11.Mechanism{mech},
		tpl,
	)
	if err != nil {
		return SecretKey{}, newError(err, "could not generate keys")
	}

	return SecretKey{object{s, k}}, nil
}

// SignHMAC256 signs the given data with the key using HMAC-SHA256.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k *SecretKey) SignHMAC256(raw []byte) ([]byte, error) {
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}
	if err := k.sess.tok.m.Raw().SignInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, newError(err, "could not begin signing operation")
	}

	data, err := k.sess.tok.m.Raw().Sign(k.sess.raw, raw)
	if err != nil {
		return nil, newError(err, "could not complete signing operation")
	}
	return data, nil
}

// GenSecretWrapMechanism specifies the key wrapping mechanism to use.
type GenSecretWrapMechanism int

const (
	// GenSecretWrapMechanismRsaOaep uses RSA-OAEP for key wrapping.
	GenSecretWrapMechanismRsaOaep GenSecretWrapMechanism = iota
	// GenSecretWrapMechanismRsaPcks uses RSA-PKCS for key wrapping.
	GenSecretWrapMechanismRsaPcks
)

// Wrap wraps the key with the given public key using the specified mechanism.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k *SecretKey) Wrap(wk PublicKey, m GenSecretWrapMechanism) ([]byte, error) {
	o := k.object
	var mech []*pkcs11.Mechanism
	switch m {
	case GenSecretWrapMechanismRsaPcks:
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	case GenSecretWrapMechanismRsaOaep:
		mech = []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP,
				pkcs11.NewOAEPParams(
					pkcs11.CKM_SHA256,
					pkcs11.CKG_MGF1_SHA256,
					pkcs11.CKZ_DATA_SPECIFIED,
					nil,
				),
			),
		}
	default:
		return nil, fmt.Errorf("unsupported mechanism: %d", m)
	}
	ciph, err := k.sess.tok.m.Raw().WrapKey(k.sess.raw, mech, wk.raw, o.raw)
	if err != nil {
		return nil, fmt.Errorf("could not perform wrapping operation: %w", err)
	}
	return ciph, nil
}

// UnwrapGenSecret unwraps the key using the given private key and mechanism.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (s *Session) UnwrapGenSecret(key []byte, pko PrivateKey, m GenSecretWrapMechanism, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, opts.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}
	s.tok.m.appendAttrKeyID(&tpl)

	var mech []*pkcs11.Mechanism
	switch m {
	case GenSecretWrapMechanismRsaPcks:
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	case GenSecretWrapMechanismRsaOaep:
		mech = []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP,
				pkcs11.NewOAEPParams(
					pkcs11.CKM_SHA256,
					pkcs11.CKG_MGF1_SHA256,
					pkcs11.CKZ_DATA_SPECIFIED,
					nil,
				),
			),
		}
	default:
		return SecretKey{}, fmt.Errorf("unsupported mechanism: %d", m)
	}

	sk, err := s.tok.m.Raw().UnwrapKey(s.raw, mech, pko.object.raw, key, tpl)
	if err != nil {
		return SecretKey{}, fmt.Errorf("could not perform wrapping operation: %w", err)
	}
	return SecretKey{object{s, sk}}, nil
}

// ImportGenericSecret imports key material that can be used as a precursor for derivation.
//
// Such keys cannot be exported via ExportKey(), but the extractibility settings
// may (depending on the HSM) affect extractibility of derived keys.
func (s *Session) ImportGenericSecret(key []byte, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}
	s.tok.m.appendAttrKeyID(&tpl)

	k, err := s.tok.m.Raw().CreateObject(s.raw, tpl)
	if err != nil {
		return SecretKey{}, newError(err, "could not import key")
	}

	return SecretKey{object{s, k}}, nil
}
