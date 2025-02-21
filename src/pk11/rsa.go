// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/miekg/pkcs11"
)

// Generate RSA generates an RSA keypair with the given bit width for the public
// modulus and the given public exponent.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (s *Session) GenerateRSA(modBits uint, pubExp uint, opts *KeyOptions) (KeyPair, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
	sensitive := !opts.Extractable
	if s.tok.m.hsmType == HSMTypeHW {
		sensitive = true
	}

	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modBits),
		// E needs to be in big endian!
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(pubExp)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "pubRSA"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}

	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "privRSA"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}

	if opts.Wrapping {
		pubTpl = append(pubTpl, pkcs11.NewAttribute(pkcs11.CKA_WRAP, true))
		privTpl = append(privTpl, pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true))
	}

	if opts.Encryption {
		pubTpl = append(pubTpl, pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true))
		privTpl = append(privTpl, pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
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

func (s *Session) importRSAPrivate(key *rsa.PrivateKey, opts *KeyOptions) (PrivateKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	key.Precompute()
	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		// E needs to be in big endian!
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, key.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, key.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, key.Primes[1].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, key.Precomputed.Dp.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, key.Precomputed.Dq.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, key.Precomputed.Qinv.Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}

	if opts.Wrapping {
		tpl = append(tpl, pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true))
	}

	if opts.Encryption {
		tpl = append(tpl, pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
	}

	s.tok.m.appendAttrKeyID(&tpl)

	k, err := s.tok.m.Raw().CreateObject(s.raw, tpl)
	if err != nil {
		return PrivateKey{}, newError(err, "could not import private key")
	}

	return PrivateKey{object{s, k}}, nil
}

// SignRSAPKCS1v15 creates new RSA-PKCS#1 v1.5 signature using this object as the private key.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignRSAPKCS1v15(hash crypto.Hash, message []byte) ([]byte, error) {
	hashed, err := makeHash(hash, message)
	if err != nil {
		return nil, err
	}
	return k.SignRSAPKCS1v15PreHashed(hash, hashed)
}

// SignRSAPKCS1v15PreHashed creates new RSA-PKCS#1 v1.5 signature using this object as the private key.
//
// This function expects the message to be pre-hashed, and exists to support RSASigner type; prefer
// SignRSAPKCS1v15 when possible.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignRSAPKCS1v15PreHashed(hash crypto.Hash, hashed []byte) ([]byte, error) {
	var prefix []byte
	switch hash {
	case crypto.SHA256:
		prefix = []byte{
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
			0x00, 0x04, 0x20,
		}
	case crypto.SHA384:
		prefix = []byte{
			0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
			0x00, 0x04, 0x30,
		}
	case crypto.SHA512:
		prefix = []byte{
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
			0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
			0x00, 0x04, 0x40,
		}
	default:
		return nil, fmt.Errorf("unknown hash function: %s", hash)
	}

	raw := append(prefix, hashed...)

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := k.sess.tok.m.Raw().SignInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, newError(err, "could not begin signing operation")
	}

	data, err := k.sess.tok.m.Raw().Sign(k.sess.raw, raw)
	if err != nil {
		return nil, newError(err, "could not complete signing operation")
	}
	return data, nil
}

// SignRSAPSS creates new RSA-PSS signature using this object as the private key.
//
// This function always uses MGF1 with the same hash specified for the actual hashing,
// because it's the only one anyone will ever define.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignRSAPSS(opts *rsa.PSSOptions, message []byte) ([]byte, error) {
	hashed, err := makeHash(opts.Hash, message)
	if err != nil {
		return nil, err
	}
	return k.SignRSAPSSPreHashed(opts, hashed)
}

// SignRSAPSSPreHashed creates new RSA-PSS signature using this object as the private key.
//
// This function always uses MGF1 with the same hash specified for the actual hashing,
// because it's the only one anyone will ever define.
//
// This function expects the message to be pre-hashed, and exists to support RSASigner type; prefer
// SignRSAPSS when possible.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignRSAPSSPreHashed(opts *rsa.PSSOptions, hashed []byte) ([]byte, error) {
	var hashMech, mgfMech uint
	switch opts.Hash {
	case crypto.SHA256:
		hashMech = pkcs11.CKM_SHA256
		mgfMech = pkcs11.CKG_MGF1_SHA256
	case crypto.SHA384:
		hashMech = pkcs11.CKM_SHA384
		mgfMech = pkcs11.CKG_MGF1_SHA384
	case crypto.SHA512:
		hashMech = pkcs11.CKM_SHA512
		mgfMech = pkcs11.CKG_MGF1_SHA512
	default:
		return nil, fmt.Errorf("unknown hash function: %s", opts.Hash)
	}

	saltLen := opts.SaltLength
	switch saltLen {
	case rsa.PSSSaltLengthAuto:
		n, err := k.Attr(pkcs11.CKA_MODULUS)
		if err != nil {
			return nil, err
		}
		saltLen = len(n) - opts.Hash.Size() - 2
	case rsa.PSSSaltLengthEqualsHash:
		saltLen = opts.Hash.Size()
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(
		pkcs11.CKM_RSA_PKCS_PSS,
		pkcs11.NewPSSParams(hashMech, mgfMech, uint(saltLen)),
	)}

	if err := k.sess.tok.m.Raw().SignInit(k.sess.raw, mech, k.raw); err != nil {
		return nil, newError(err, "could not begin signing operation")
	}

	data, err := k.sess.tok.m.Raw().Sign(k.sess.raw, hashed)
	if err != nil {
		return nil, newError(err, "could not complete signing operation")
	}
	return data, nil
}

// RSASigner is a crypto.Signer backed by a PrivateKey.
type RSASigner struct {
	// The public key, which may not actually live on the device itself.
	*rsa.PublicKey
	// The private key, which is stored on-device.
	PrivateKey
}

// NewRsaSigner creates a new signer by looking up the corresponding public
// key on the HSM and exporting it.
func NewRSASigner(k PrivateKey) (RSASigner, error) {
	pub, err := k.FindPublicKey()
	if err != nil {
		return RSASigner{}, err
	}
	export, err := pub.ExportKey()
	if err != nil {
		return RSASigner{}, err
	}
	rsaPub, ok := export.(*rsa.PublicKey)
	if !ok {
		return RSASigner{}, fmt.Errorf("expected *rsa.PublicKey, got something else: %s", reflect.TypeOf(export))
	}

	return RSASigner{rsaPub, k}, nil
}

// Public returns the public key.
//
// This is part of interface crypto.Signer.
func (s RSASigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs digest with the signer's private key.
//
// If opts is an *rsa.PSSOptions, it will be used for PSS; otherwise, we fall back to PKCS#1 v1.5.
//
// The HSM provides randomness, so the randomness source parameter is ignored (and may even be nil!).
//
// This is part of interface crypto.Signer.
func (s RSASigner) Sign(ignored io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts, ok := opts.(*rsa.PSSOptions); ok {
		return s.PrivateKey.SignRSAPSSPreHashed(opts, digest)
	}
	return s.PrivateKey.SignRSAPKCS1v15PreHashed(opts.HashFunc(), digest)
}

func (o object) exportRSAPublic() (*rsa.PublicKey, error) {
	attrs, err := o.Attrs(pkcs11.CKA_MODULUS, pkcs11.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, newError(err, "could not retrieve public key contents")
	}

	d := new(big.Int)
	d.SetBytes(attrs[0].Value)

	e := int(bytes2uint(attrs[1].Value))

	return &rsa.PublicKey{d, e}, nil
}

func (o object) exportRSAPrivate() (*rsa.PrivateKey, error) {
	public, err := o.exportRSAPublic()
	if err != nil {
		return nil, err
	}

	attrs, err := o.Attrs(
		pkcs11.CKA_PRIVATE_EXPONENT,
		pkcs11.CKA_PRIME_1,
		pkcs11.CKA_PRIME_2,
	)
	if err != nil {
		return nil, newError(err, "could not retrieve private key components")
	}

	var d, p, q big.Int
	d.SetBytes(attrs[0].Value)
	p.SetBytes(attrs[1].Value)
	q.SetBytes(attrs[2].Value)

	return &rsa.PrivateKey{
		PublicKey: *public,
		D:         &d,
		Primes:    []*big.Int{&p, &q},
	}, nil
}
