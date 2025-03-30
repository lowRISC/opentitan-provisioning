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

// TokenOp specifies the operation to perform on the token.
type TokenOp int

const (
	// TokenOpRaw indicates that the token should be generated as a raw token.
	TokenOpRaw TokenOp = iota
	// TokenOpHashedOtLcToken indicates that the token should be generated
	// as a hashed OT/LC token.
	TokenOpHashedOtLcToken
)

// TokenType specifies the type of the token to generate.
type TokenType int

const (
	// TokenTypeSecurityHi indicates that the token should be derived from a
	//  high security seed.
	TokenTypeSecurityHi TokenType = iota
	// TokenTypeSecurityLo indicates that the token should be derived from a
	// low security seed.
	TokenTypeSecurityLo
	// TokenTypeKeyGen indicates that the token should be derived from a new
	// seed.
	TokenTypeKeyGen
)

// Parameters for GenerateTokens().
type TokenParams struct {
	Diversifier  string
	Op           TokenOp
	Type         TokenType
	SeedLabel    string
	SizeInBits   uint
	Sku          string
	Wrap         WrappingMechanism
	WrapKeyLabel string
}

type TokenResult struct {
	Token       []byte
	WrappedKey  []byte
	Diversifier string
}

// SE is an interface representing a secure element, which may be implemented
// by various hardware modules under the hood.
//
// An SE provides privileged access to cryptographic operations using high-value
// assets, such as long-lived root secrets.
type SE interface {
	// Generates tokens.
	//
	// These tokens may be used as:
	//   - Wafer Authentication tokens, or
	//   - Lifecycle tokens.
	//
	// Returns: slice of `TokenResult` objects.
	GenerateTokens(params []*TokenParams) ([]TokenResult, error)

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
