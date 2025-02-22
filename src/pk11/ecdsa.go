// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/miekg/pkcs11"
)

// oid converts a Curve into its corresponding named curve OID.
func oid(c elliptic.Curve) ([]byte, error) {
	switch c.Params().Name {
	case "P-256":
		// ascii2der <<< "OBJECT_IDENTIFIER { 1.2.840.10045.3.1.7 }" | xxd -i
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil
	case "P-384":
		// ascii2der <<< "OBJECT_IDENTIFIER { 1.3.132.0.34 }" | xxd -i
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, nil
	case "P-521":
		// ascii2der <<< "OBJECT_IDENTIFIER { 1.2.840.10045.4.3.4 }" | xxd -i
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04}, nil
	default:
		return nil, fmt.Errorf("unsupported curve: %s", c.Params().Name)
	}
}

var oid2Curve = map[string]elliptic.Curve{
	string([]byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}): elliptic.P256(),
	string([]byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}):                   elliptic.P384(),
	string([]byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x07, 0x03, 0x04}): elliptic.P521(),
}

// GenerateECDSA generates an ECDSA signing keypair on the specified curve.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (s *Session) GenerateECDSA(curve elliptic.Curve, opts *KeyOptions) (KeyPair, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	oid, err := oid(curve)
	if err != nil {
		return KeyPair{}, err
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)
	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}
	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
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

func (s *Session) importECDSAPrivate(key *ecdsa.PrivateKey, opts *KeyOptions) (PrivateKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	pk := &key.PublicKey
	oid, err := oid(pk.Curve)
	if err != nil {
		return PrivateKey{}, err
	}

	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key.D.Bytes()),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, !opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, opts.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, opts.Token),
	}
	s.tok.m.appendAttrKeyID(&tpl)

	k, err := s.tok.m.Raw().CreateObject(s.raw, tpl)
	if err != nil {
		return PrivateKey{}, newError(err, "could not import private key")
	}

	return PrivateKey{object{s, k}}, nil
}

// SignECDSA creates new ECDSA signature using this object as the private key.
//
// The signature is returned as a pair of scalars in big-endian order.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignECDSA(hash crypto.Hash, message []byte) (r, s []byte, err error) {
	hashed, err := makeHash(hash, message)
	if err != nil {
		return
	}

	return k.SignECDSAPreHashed(hashed)
}

// SignECDSA creates new ECDSA signature using this object as the private key.
//
// The signature is returned as a pair of scalars in big-endian order.
//
// This function expects the message to be pre-hashed, and exists to support ECDSASigner type; prefer
// SignECDSA when possible.
//
// This operation can be quite slow, so it is recommended to call it from another
// goroutine.
func (k PrivateKey) SignECDSAPreHashed(hashed []byte) (r, s []byte, err error) {
	// Although a bit general, we stick to using CKM_ECDSA here for portability to the
	// most HSMs possible.
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	if err = k.sess.tok.m.Raw().SignInit(k.sess.raw, mech, k.raw); err != nil {
		err = newError(err, "could not begin signing operation")
		return
	}

	data, err := k.sess.tok.m.Raw().Sign(k.sess.raw, hashed)
	if err != nil {
		err = newError(err, "could not complete signing operation")
		return
	}

	r, s = data[:len(data)/2], data[len(data)/2:]
	return
}

// ECDSASigner is a crypto.Signer backed by a PrivateKey.
type ECDSASigner struct {
	// The public key, which may not actually live on the device itself.
	*ecdsa.PublicKey
	// The private key, which is stored on-device.
	PrivateKey
}

// NewECDSASigner creates a new signer by looking up the corresponding public
// key on the HSM and exporting it.
func NewECDSASigner(k PrivateKey) (ECDSASigner, error) {
	pub, err := k.FindPublicKey()
	if err != nil {
		return ECDSASigner{}, err
	}
	export, err := pub.ExportKey()
	if err != nil {
		return ECDSASigner{}, err
	}
	eccPub, ok := export.(*ecdsa.PublicKey)
	if !ok {
		return ECDSASigner{}, fmt.Errorf("expected *ecdsa.PublicKey, got something else: %s", reflect.TypeOf(export))
	}

	return ECDSASigner{eccPub, k}, nil
}

// Public returns the public key.
//
// This is part of interface crypto.Signer.
func (s ECDSASigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign signs digest with the signer's private key.
//
// The HSM provides randomness, so the randomness source parameter is ignored (and may even be nil!).
// The opts parameter is also ignored, though it should be the same crypto.Hash that was used to
// hash the digest.
//
// This function returns an ASN-1 DER-encoded signature, i.e.:
//
//	signature ::= SEQUENCE { r INTEGER; s INTEGER; }
//
// This is part of interface crypto.Signer.
func (s ECDSASigner) Sign(ignored io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	rb, sb, err := s.PrivateKey.SignECDSAPreHashed(digest)
	if err != nil {
		return nil, err
	}

	var sig struct{ R, S *big.Int }
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(rb)
	sig.S.SetBytes(sb)

	return asn1.Marshal(sig)
}

func (o object) exportECDSAPublic() (*ecdsa.PublicKey, error) {
	attrs, err := o.Attrs(pkcs11.CKA_EC_PARAMS, pkcs11.CKA_EC_POINT)
	if err != nil {
		return nil, newError(err, "could not retrieve public key contents")
	}
	oid, qDer := attrs[0].Value, attrs[1].Value

	curve, ok := oid2Curve[string(oid)]
	if !ok {
		return nil, fmt.Errorf("unknown curve OID: %v", oid)
	}

	var q []byte
	if _, err := asn1.Unmarshal(qDer, &q); err != nil {
		return nil, newError(err, "could not parse curve point")
	}

	x, y := elliptic.Unmarshal(curve, q)
	if x == nil {
		return nil, fmt.Errorf("could not parse %x as an uncompressed curve point", q)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (o object) exportECDSAPrivate() (*ecdsa.PrivateKey, error) {
	pubObj, err := PrivateKey{o}.FindPublicKey()
	if err != nil {
		return nil, err
	}
	public, err := pubObj.exportECDSAPublic()
	if err != nil {
		return nil, err
	}

	dBytes, err := o.Attr(pkcs11.CKA_VALUE)
	if err != nil {
		return nil, newError(err, "could not retrieve private key components")
	}

	d := new(big.Int)
	d.SetBytes(dBytes)

	return &ecdsa.PrivateKey{
		PublicKey: *public,
		D:         d,
	}, nil
}
