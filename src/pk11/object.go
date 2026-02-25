// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"reflect"

	"github.com/miekg/pkcs11"
)

type ClassAttribute *pkcs11.Attribute

var (
	ClassPublicKey  = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY)
	ClassPrivateKey = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)
	ClassSecretKey  = pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY)
)

// UID creates a new Attribute representing a particular UID value.
func UID(uid []byte) *pkcs11.Attribute {
	return pkcs11.NewAttribute(pkcs11.CKA_ID, uid)
}

// Label creates a new Attribute representing a particular label value.
func Label(label string) *pkcs11.Attribute {
	return pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label))
}

// KeyOptions is passed into key-creation functions for specifying how the
// HSM should treat it.
type KeyOptions struct {
	// An extractible key can be pulled out of the HSM, such as through export
	// or wrapping.
	//
	// Not all HSMs may permit this on some key types.
	Extractable bool
	// Sensitive keys cannot be exported in plaintext on the HSM.
	Sensitive bool
	// Set to true to make key a token object or false to make a session
	// object.
	Token bool
	// Set to true to allow the key to be used for encryption/decryption.
	Encryption bool
	// Set to true to allow the key to be used for wrapping/unwrapping other keys.
	Wrapping bool
}

// KeyPair is the result of a key generation operation.
type KeyPair struct {
	PublicKey
	PrivateKey
}

// Object represents a PKCS#11 object: a bag of untyped data keyed by integers.
// These key-value pairs are called "attributes" and can be queried to obtain
// information about the object.
//
// Objects may also be copied or destroyed. A Session can be used to create
// new objects.
type Object interface {
	// Attrs retrieves arbitrary attributes from an object.
	Attrs(types ...uint) ([]*pkcs11.Attribute, error)
	// Attr retrieves a single attribute from an object.
	Attr(typ uint) ([]byte, error)
	// Int retrieves a single attribute from an object and interprets it as an
	// integer.
	Int(typ uint) (uint, error)
	// Destroy destroys an object, which will be unusable after it returns
	// successfully.
	Destroy() error
	// UID retrieves this object's HSM-assigned unique identifier.
	//
	// This value can be used to retrieve the object at a later date.
	UID() ([]byte, error)
	// Label retrives the object's assigned label if available.
	Label() (string, error)
	// SetLabel sets the object's CKA_LABEL attribute.
	SetLabel(string) error
	// Session returns the session handle managing this object.
	Session() *Session
}

// Keys are Objects which represent some kind of cryptographic key stored on the
// HSM.
type Key interface {
	Object
	// ExportKey exports this key out of the HSM.
	ExportKey() (any, error)
}

// PublicKey is an object that refers to a public key.
//
// The underlying object is assumed to always be a public key
// (PKO_PUBLIC_KEY).
type PublicKey struct{ object }

// PrivateKey is an object that refers to a private key.
//
// The underlying object is assumed to always be a private key
// (PKO_PRIVATE_KEY).
type PrivateKey struct{ object }

// SecretKey is an object that refers to a symmetric/secret key.
//
// The underlying object is assumed to always be a symmetric key
// (PKO_SECRET_KEY).
type SecretKey struct{ object }

// object wraps a handle to a PKCS#11 object accessed during a session.
type object struct {
	sess *Session
	raw  pkcs11.ObjectHandle
}

// find finds all objects visible to this session with the given attributes.
func (s *Session) find(attrs ...*pkcs11.Attribute) ([]object, error) {
	if err := s.tok.m.Raw().FindObjectsInit(s.raw, attrs); err != nil {
		return nil, newError(err, "could not begin search for objects")
	}

	var objs []object
	for i := 0; ; i++ {
		raw, _, err := s.tok.m.Raw().FindObjects(s.raw, 32)
		if err != nil {
			return nil, newError(err, "could not continue search for objects after %d iterations", i)
		}
		if len(raw) == 0 {
			break
		}

		for _, o := range raw {
			objs = append(objs, object{s, o})
		}
	}

	if err := s.tok.m.Raw().FindObjectsFinal(s.raw); err != nil {
		return nil, newError(err, "could not complete search for objects")
	}

	return objs, nil
}

// findUnique searches for the unique object with the given class and UID.
//
// Since finding two keys with the same class and UID is impossible, this function panics
// in such a scenario.
func (s *Session) findUnique(class *pkcs11.Attribute, uid []byte) (object, error) {
	objs, err := s.find(class, UID(uid))
	if err != nil {
		return object{}, err
	}

	switch len(objs) {
	case 0:
		return object{}, fmt.Errorf("could not find object with UID %v", uid)
	case 1:
		return objs[0], nil
	default:
		return object{}, fmt.Errorf("found multiple objects with UID %v", uid)
	}
}

// findUniqueByLabel searches for the unique object with the given class and Label.
//
// Since finding two keys with the same class and Label is impossible, this function returns
// an error in such a scenario.
func (s *Session) findUniqueByLabel(class *pkcs11.Attribute, label string) (object, error) {
	objs, err := s.find(class, Label(label))
	if err != nil {
		return object{}, err
	}

	switch len(objs) {
	case 0:
		return object{}, fmt.Errorf("could not find object with LABEL %q", label)
	case 1:
		return objs[0], nil
	default:
		return object{}, fmt.Errorf("found multiple objects with LABEL %q", label)
	}
}

// FindPublicKey finds the unique public key object with the given UID.
func (s *Session) FindPublicKey(uid []byte) (PublicKey, error) {
	o, err := s.findUnique(ClassPublicKey, uid)
	return PublicKey{o}, err
}

// FindPrivateKey finds the unique private key object with the given UID.
func (s *Session) FindPrivateKey(uid []byte) (PrivateKey, error) {
	o, err := s.findUnique(ClassPrivateKey, uid)
	return PrivateKey{o}, err
}

// FindKeyByLabel finds the key object with the given label.
func (s *Session) FindKeyByLabel(classKey ClassAttribute, label string) (object, error) {
	o, err := s.findUniqueByLabel(classKey, label)
	return o, err
}

// FindSecretKey finds the unique symmetric key object with the given UID.
func (s *Session) FindSecretKey(uid []byte) (SecretKey, error) {
	o, err := s.findUnique(ClassSecretKey, uid)
	return SecretKey{o}, err
}

// FindPublicKey finds the unique public and private key objects with the given UID.
func (s *Session) FindKeyPair(uid []byte) (KeyPair, error) {
	pub, err := s.FindPublicKey(uid)
	if err != nil {
		return KeyPair{}, nil
	}
	priv, err := s.FindPrivateKey(uid)
	if err != nil {
		return KeyPair{}, nil
	}
	return KeyPair{pub, priv}, nil
}

// FindAllKeys returns all accessible keys stored in the HSM.
//
// Values in the array will be either PublicKey, PrivateKey, or SecretKey.
func (s *Session) FindAllKeys() ([]Key, error) {
	var keys []Key

	objs, err := s.find(ClassPublicKey)
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		keys = append(keys, PublicKey{o})
	}

	objs, err = s.find(ClassPrivateKey)
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		keys = append(keys, PrivateKey{o})
	}

	objs, err = s.find(ClassSecretKey)
	if err != nil {
		return nil, err
	}
	for _, o := range objs {
		keys = append(keys, SecretKey{o})
	}

	return keys, nil
}

func (o object) Session() *Session {
	return o.sess
}

// Attrs retrieves arbitrary attributes from an object.
func (o object) Attrs(types ...uint) ([]*pkcs11.Attribute, error) {
	var attrs []*pkcs11.Attribute
	for _, t := range types {
		attrs = append(attrs, &pkcs11.Attribute{Type: t})
	}

	attrs, err := o.sess.tok.m.Raw().GetAttributeValue(o.sess.raw, o.raw, attrs)
	if err != nil {
		err = newError(err, "could not retrieve attributes: %v", types)
	}
	return attrs, err
}

// Attr retrieves a single attribute from an object.
func (o object) Attr(typ uint) ([]byte, error) {
	attrs, err := o.Attrs(typ)
	if err != nil {
		return nil, err
	}
	return attrs[0].Value, nil
}

func bytes2uint(buf []byte) uint {
	var x uint
	for i, b := range buf {
		x |= uint(b) << (i * 8)
	}
	return x
}

// Int retrieves a single attribute from an object and interprets it as an integer.
func (o object) Int(typ uint) (uint, error) {
	attr, err := o.Attr(typ)
	if err != nil {
		return 0, err
	}

	return bytes2uint(attr), nil
}

// Destroy destroys an object, which will be unusable after it returns successfully.
func (o object) Destroy() error {
	if err := o.sess.tok.m.Raw().DestroyObject(o.sess.raw, o.raw); err != nil {
		return newError(err, "could not destroy object")
	}
	return nil
}

// UID retrieves this object's HSM-assigned unique identifier.
//
// This value can be used to retrieve the object at a later date.
func (o object) UID() ([]byte, error) {
	a, err := o.Attrs(pkcs11.CKA_ID) // package pkcs11 seems to have misnamed this.
	if err != nil {
		return nil, err
	}
	return a[0].Value, nil
}

// Label retrives the object's assigned label if available.
func (o object) Label() (string, error) {
	label, err := o.Attr(pkcs11.CKA_LABEL)
	if err != nil {
		return "", err
	}
	return string(label), nil
}

// SetLabel sets the object's CKA_LABEL attribute.
func (o object) SetLabel(label string) error {
	err := o.sess.tok.m.Raw().SetAttributeValue(o.sess.raw, o.raw, []*pkcs11.Attribute{Label(label)})
	if err != nil {
		return fmt.Errorf("could not set label attribute: %v", err)
	}
	return nil
}

// GenerateRandom returns random data extracted from the HSM.
func (s *Session) GenerateRandom(length int) ([]byte, error) {
	return s.tok.m.Raw().GenerateRandom(s.raw, length)
}

// ImportKey imports a key into this session.
//
// key may be any type among *rsa.PrivateKey, *ecdsa.PrivateKey, or AESKey;
// the returned type will be a PKCS#11 object corresponding to the Go type
// of the imported key. For example, an *rsa.PrivateKey will become a
// PrivateKey.
func (s *Session) ImportKey(key any, opts *KeyOptions) (Key, error) {
	// Public keys are currently not supported, but this will be the place
	// to add them once we need them.
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return s.importRSAPrivate(k, opts)
	case *ecdsa.PrivateKey:
		return s.importECDSAPrivate(k, opts)
	case AESKey:
		return s.importAESRaw(k, opts)
	default:
		return nil, fmt.Errorf("unknown key type %s", reflect.TypeOf(key))
	}
}

// ExportKey exports this key out of the HSM.
//
// The type of the returned object depends on the type of key being exported:
// - ECDSA keys are *ecdsa.PublicKey.
// - RSA keys are *rsa.PublicKey.
func (k PublicKey) ExportKey() (any, error) {
	kType, err := k.Int(pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	switch kType {
	case pkcs11.CKK_RSA:
		// Defined in rsa.go
		return k.exportRSAPublic()
	case pkcs11.CKK_ECDSA:
		// Defined in ecdsa.go
		return k.exportECDSAPublic()
	default:
		return nil, fmt.Errorf("cannot parse key: type %x", kType)
	}
}

// ExportKey exports this key out of the HSM.
//
// The type of the returned object depends on the type of key being exported:
// - ECDSA keys are *ecdsa.PrivateKey.
// - RSA keys are *rsa.PrivateKey.
func (k PrivateKey) ExportKey() (any, error) {
	kType, err := k.Int(pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	switch kType {
	case pkcs11.CKK_RSA:
		// Defined in rsa.go
		return k.exportRSAPrivate()
	case pkcs11.CKK_ECDSA:
		// Defined in ecdsa.go
		return k.exportECDSAPrivate()
	default:
		return nil, fmt.Errorf("cannot parse key: type %x", kType)
	}
}

// ExportKey exports this key out of the HSM.
//
// The type of the returned object depends on the type of key being exported:
// - AES keys are AESKey.
func (k SecretKey) ExportKey() (any, error) {
	kType, err := k.Int(pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	switch kType {
	case pkcs11.CKK_AES:
		bytes, err := k.Attr(pkcs11.CKA_VALUE)
		return AESKey(bytes), err

	default:
		return nil, fmt.Errorf("cannot parse key: type %x", kType)
	}
}

// FindPublicKey tries to find the corresponding public key to this private key.
//
// "Corresponding" is defined as "same UID", which may not be present.
func (k PrivateKey) FindPublicKey() (PublicKey, error) {
	uid, err := k.UID()
	if err != nil {
		return PublicKey{}, err
	}

	return k.Session().FindPublicKey(uid)
}

// Signer creates a crypto.Signer wrapping this private key.
func (k PrivateKey) Signer() (crypto.Signer, error) {
	kType, err := k.Int(pkcs11.CKA_KEY_TYPE)
	if err != nil {
		return nil, err
	}

	switch kType {
	case pkcs11.CKK_RSA:
		// Defined in rsa.go
		return NewRSASigner(k)
	case pkcs11.CKK_ECDSA:
		// Defined in ecdsa.go
		return NewECDSASigner(k)
	case CKK_MLDSA:
		return MLDSASigner{k}, nil
	default:
		return nil, fmt.Errorf("not a known private key type: %x", kType)
	}
}
