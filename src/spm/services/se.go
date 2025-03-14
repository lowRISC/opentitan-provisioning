// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package se provides interfaces for working with different kinds of Secure
// Elements.
package se

import (
	"crypto/x509"
)

// WrappingMechanism specifies the wrapping mechanism for the key.
type WrappingMechanism int

const (
	// WrappingMechanismNone indicates that the key should not be wrapped.
	WrappingMechanismNone WrappingMechanism = iota
	// WrappingMechanismRSAPCKS indicates that the key should be wrapped using
	// RSA PKCS#1.5.
	WrappingMechanismRSAPCKS
	// WrappingMechanismRSAOAEP indicates that the key should be wrapped using
	// RSA OAEP.
	WrappingMechanismRSAOAEP
	// WrappingMechanismAESKWP indicates that the key should be wrapped using
	// AES Key Wrap with Padding.
	WrappingMechanismAESKWP
	// WrappingMechanismAESGCM indicates that the key should be wrapped using
	// AES GCM.
	WrappingMechanismAESGCM
)

// Parameters for EndorseCert().
type EndorseCertParams struct {
	// Key label. Used to identify the key in the HSM.
	KeyLabel string
	// Signature algorithm to use.
	SignatureAlgorithm x509.SignatureAlgorithm
}

// SymmetricKeyOp specifies the operation to perform on the key.
type SymmetricKeyOp int

const (
	// SymmetricKeyOpRaw indicates that the key should be generated as a raw key.
	SymmetricKeyOpRaw SymmetricKeyOp = iota
	// SymmetricKeyOpHashedOtLcToken indicates that the key should be generated
	// as a hashed OT/LC token.
	SymmetricKeyOpHashedOtLcToken
)

// SymmetricKeyType specifies the type of the key to generate.
type SymmetricKeyType int

const (
	// SymmetricKeyTypeSecurityHi indicates that the key should be a high
	// security key.
	SymmetricKeyTypeSecurityHi SymmetricKeyType = iota
	// SymmetricKeyTypeSecurityLo indicates that the key should be a low
	// security key.
	SymmetricKeyTypeSecurityLo
	// SymmetricKeyTypeKeyGen indicates that the key should be a new key.
	SymmetricKeyTypeKeyGen
)

// Parameters for GenerateSymmetricKeys().
type SymmetricKeygenParams struct {
	Diversifier  string
	KeyOp        SymmetricKeyOp
	KeyType      SymmetricKeyType
	SeedLabel    string
	SizeInBits   uint
	Sku          string
	Wrap         WrappingMechanism
	WrapKeyLabel string
}

type SymmetricKeyResult struct {
	Key         []byte
	WrappedKey  []byte
	Diversifier string
}

// SE is an interface representing a secure element, which may be implemented
// by various hardware modules under the hood.
//
// An SE provides privileged access to cryptographic operations using high-value
// assets, such as long-lived root secrets.
type SE interface {
	// Generates symmetric keys.
	//
	// These keys are generated via the HKDF mechanism and may be used as:
	//   - Wafer Authentication Secrets, or
	//   - Lifecycle Tokens.
	//
	// Returns: slice of `SymmetricKeyResult` objects.
	GenerateSymmetricKeys(params []*SymmetricKeygenParams) ([]SymmetricKeyResult, error)

	// Endorses a certificate.
	//
	// This operation is used to sign a certificate with the SE's private key.
	// The certificate is provided in raw form, and the SE will return the
	// signed certificate in DER format.
	//
	// Note: only ECDSA signature algorithms are currently supported.
	//
	// Returns: Raw signature in bytes.
	EndorseCert(tbs []byte, params EndorseCertParams) ([]byte, error)

	// EndorseData hashes and signs an arbitrary data payload.
	//
	// This operation is used to sign an array of bytes with the SE's private key.
	// The bytes are provided in raw form, and the SE will return the signature in
	// ASN.1 DER encoded form.
	//
	// Note: only ECDSA signature algorithms are currently supported.
	//
	// Returns: ECDSA signature (ASN.1 DER encoded).
	EndorseData(data []byte, params EndorseCertParams) ([]byte, []byte, error)

	// VerifySession verifies that a session to the HSM for a given SKU is active
	VerifySession() error
}
