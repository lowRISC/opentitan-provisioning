// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// AESKey is an AES key on the Go side.
//
// Most Go functions use []byte to refer to AES keys, but giving it a specific
// type allows us to be more specific in interfaces that take in arbitrary key
// types.
type AESKey []byte

// GenerateAES generates an AES key with the given number of bits.
//
// If sensitive is false, the key will be extractable via ExportKey().
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (s *Session) GenerateAES(keyBitLen uint, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	if keyBitLen%8 != 0 || keyBitLen < 128 {
		return SecretKey{}, fmt.Errorf("keyBitLen must be a multiple of 8 >= 128; got %d", keyBitLen)
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBitLen/8),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, opts.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
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

func (s *Session) importAESRaw(key AESKey, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	if len(key) < 16 {
		return SecretKey{}, fmt.Errorf("key must be at least 128 bits long, got %d", len(key)*8)
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte(key)),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, opts.Sensitive),
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

// SealAESGCM performs a AES-GCM encryption, using this object as the key.
//
// iv is the initialization vector; aad is the additional data for the AEAD, which may be nil.
// Some HSMs may provide their own IV; regardless of whether the user-provided IV is used, the
// actual IV used for encryption is returned as well.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k SecretKey) SealAESGCM(iv, aad []byte, tagBits int, plaintext []byte) (ciphertext, actualIV []byte, err error) {
	if tagBits%8 != 0 || tagBits < 96 || tagBits > 128 {
		return nil, nil, fmt.Errorf("tagBits must be a multiple of 8 between 96 and 128; got %d", tagBits)
	}

	params := pkcs11.NewGCMParams(iv, aad, tagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := k.sess.tok.m.Raw().EncryptInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, nil, newError(err, "could not begin encryption operation")
	}

	ciph, err := k.sess.tok.m.Raw().Encrypt(k.sess.raw, plaintext)
	if err != nil {
		return nil, nil, newError(err, "could not perform encryption operation")
	}

	return ciph, params.IV(), nil
}

// UnsealAESGCM performs a AES-GCM decryption, using this object as the key.
// iv is the initialization vector; add is the additional data for the AEAD, which may be nil.
// Some HSMs may provide their own IV; regardless of whether the user-provided IV is used, the
// actual IV used for decryption is returned as well.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k SecretKey) UnsealAESGCM(iv, aad []byte, tagBits int, ciphertext []byte) ([]byte, error) {
	if tagBits%8 != 0 || tagBits < 96 || tagBits > 128 {
		return nil, fmt.Errorf("tagBits must be a multiple of 8 between 96 and 128; got %d", tagBits)
	}

	params := pkcs11.NewGCMParams(iv, aad, tagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := k.sess.tok.m.Raw().DecryptInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, newError(err, "could not begin decryption operation")
	}

	plain, err := k.sess.tok.m.Raw().Decrypt(k.sess.raw, ciphertext)
	if err != nil {
		return nil, newError(err, "could not perform decryption operation")
	}

	return plain, nil
}

// WrapAESKWP wraps a key using AES-KWP.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k SecretKey) WrapAESKWP(key Key) ([]byte, error) {
	var o object
	switch key := key.(type) {
	case SecretKey:
		o = key.object
	case PrivateKey:
		o = key.object
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)}
	ciph, err := k.sess.tok.m.Raw().WrapKey(k.sess.raw, mech, k.raw, o.raw)
	if err != nil {
		return nil, newError(err, "could not perform wrapping operation")
	}

	return ciph, nil
}

// WrapAESGCM wraps a key using AES-GCM.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k SecretKey) WrapAESGCM(key Key) (ciphertext, actualIV []byte, err error) {
	var o object
	switch key := key.(type) {
	case SecretKey:
		o = key.object
	case PrivateKey:
		o = key.object
	default:
		return nil, nil, fmt.Errorf("unsupported key type %T", key)
	}
	tagBits := 128 // The value must be a multiple of 8 between 96 and 128
	params := pkcs11.NewGCMParams(nil, nil, tagBits)
	defer params.Free()

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}

	ciph, err := k.sess.tok.m.Raw().WrapKey(k.sess.raw, mech, k.raw, o.raw)
	if err != nil {
		return nil, nil, newError(err, "could not perform wrapping operation")
	}

	iv := ciph[len(ciph)-16:]
	cipher := ciph[:len(ciph)-16]

	return cipher, iv, nil
}
