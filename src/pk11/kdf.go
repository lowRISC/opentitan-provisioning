// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"fmt"
	"reflect"

	"github.com/lowRISC/opentitan-provisioning/src/pk11/native"
	"github.com/miekg/pkcs11"
)

// pkcs11 does not provide these constants. They are not named in the usual Go
// style, but instead match those used in the PKCS#11 spec, to match the pkcs11
// package names. The leading underscore is to ensure they are private; this
// strategy is used in some
const (
	_CKK_HKDF           = 0x41
	_CKM_HKDF_DERIVE    = 0x402a
	_CKM_HKDF_DATA      = 0x402b
	_CKM_HKDF_KEY_GEN   = 0x402c
	_CKF_HKDF_SALT_NULL = 1 << 0
	_CKF_HKDF_SALT_DATA = 1 << 1
	_CKF_HKDF_SALT_KEY  = 1 << 2
)

// HKDFExtract computes `hmac(salt, s)` and uses the result to produce a new
// key, which can be used with HKDFExtract.
//
// The salt may be a byte slice, a SecretKey, or nil; in the latter case, a
// zero-filled buffer equal to the length of the hash will be used as the salt.
//
// Such keys cannot be exported via ExportKey(), but the extractibility settings
// may (depending on the HSM) affect extractibility of derived keys.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k *SecretKey) HKDFExtract(hash crypto.Hash, salt any, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	params := native.HKDFParams{Extract: true}

	switch hash {
	case crypto.SHA256:
		params.Hash = pkcs11.CKM_SHA256
	case crypto.SHA384:
		params.Hash = pkcs11.CKM_SHA384
	case crypto.SHA512:
		params.Hash = pkcs11.CKM_SHA512
	default:
		return SecretKey{}, fmt.Errorf("unknown hash function: %s", hash)
	}

	switch s := salt.(type) {
	case nil:
		params.SaltType = _CKF_HKDF_SALT_NULL
	case []byte:
		params.SaltType = _CKF_HKDF_SALT_DATA
		params.Salt = s
	case SecretKey:
		params.SaltType = _CKF_HKDF_SALT_KEY
		params.SaltKey = s.raw
	default:
		return SecretKey{}, fmt.Errorf("unknown salt type: %s", reflect.TypeOf(salt))
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, _CKK_HKDF),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
	}
	k.sess.tok.m.appendAttrKeyID(&tpl)

	rawMech := params.MakeRawMech(_CKM_HKDF_DERIVE)
	defer params.Free()

	obj, err := native.RawDeriveKey(k.sess.tok.m.Raw(), k.sess.raw, k.raw, rawMech, tpl)
	if err != nil {
		return SecretKey{}, newError(err, "could not perform key derivation operation")
	}

	return SecretKey{object{k.sess, obj}}, nil
}

// HKDFExpandAES uses a secret key created with HKDFExtract() to generate an AES key.
//
// This must use the same hash algorithm that the original intermediate key material
// was created with.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k *SecretKey) HKDFExpandAES(hash crypto.Hash, info []byte, keyBitLen uint, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}
	if keyBitLen%8 != 0 || keyBitLen < 128 {
		return SecretKey{}, fmt.Errorf("keyBitLen must be a multiple of 8 >= 128; got %d", keyBitLen)
	}

	params := native.HKDFParams{Expand: true, Info: info}

	switch hash {
	case crypto.SHA256:
		params.Hash = pkcs11.CKM_SHA256
	case crypto.SHA384:
		params.Hash = pkcs11.CKM_SHA384
	case crypto.SHA512:
		params.Hash = pkcs11.CKM_SHA512
	default:
		return SecretKey{}, fmt.Errorf("unknown hash function: %s", hash)
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBitLen/8),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
	}
	k.sess.tok.m.appendAttrKeyID(&tpl)

	rawMech := params.MakeRawMech(_CKM_HKDF_DERIVE)
	defer params.Free()

	obj, err := native.RawDeriveKey(k.sess.tok.m.Raw(), k.sess.raw, k.raw, rawMech, tpl)
	if err != nil {
		return SecretKey{}, newError(err, "could not key derivation operation")
	}

	return SecretKey{object{k.sess, obj}}, nil
}

// HKDFDeriveAES performs a single-step HKDF key derivation.
//
// The salt may be a byte slice, a SecretKey, or nil; in the latter case, a
// zero-filled buffer equal to the length of the hash will be used as the salt.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k *SecretKey) HKDFDeriveAES(hash crypto.Hash, salt any, info []byte, keyBitLen uint, opts *KeyOptions) (SecretKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}
	if keyBitLen%8 != 0 || keyBitLen < 128 {
		return SecretKey{}, fmt.Errorf("keyBitLen must be a multiple of 8 >= 128; got %d", keyBitLen)
	}

	params := native.HKDFParams{Extract: true, Expand: true, Info: info}

	switch hash {
	case crypto.SHA256:
		params.Hash = pkcs11.CKM_SHA256
	case crypto.SHA384:
		params.Hash = pkcs11.CKM_SHA384
	case crypto.SHA512:
		params.Hash = pkcs11.CKM_SHA512
	default:
		return SecretKey{}, fmt.Errorf("unknown hash function: %s", hash)
	}

	switch s := salt.(type) {
	case nil:
		params.SaltType = _CKF_HKDF_SALT_NULL
	case []byte:
		params.SaltType = _CKF_HKDF_SALT_DATA
		params.Salt = s
	case SecretKey:
		params.SaltType = _CKF_HKDF_SALT_KEY
		params.SaltKey = s.raw
	default:
		return SecretKey{}, fmt.Errorf("unknown salt type: %s", reflect.TypeOf(salt))
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyBitLen/8),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
	}
	k.sess.tok.m.appendAttrKeyID(&tpl)

	rawMech := params.MakeRawMech(_CKM_HKDF_DERIVE)
	defer params.Free()

	obj, err := native.RawDeriveKey(k.sess.tok.m.Raw(), k.sess.raw, k.raw, rawMech, tpl)
	if err != nil {
		return SecretKey{}, newError(err, "could not perform expansion operation")
	}

	return SecretKey{object{k.sess, obj}}, nil
}

// ImportKeyMaterial imports key material that can be used as a precursor for derivation.
//
// Such keys cannot be exported via ExportKey(), but the extractibility settings
// may (depending on the HSM) affect extractibility of derived keys.
func (s *Session) ImportKeyMaterial(key []byte, opts *KeyOptions) (SecretKey, error) {
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
