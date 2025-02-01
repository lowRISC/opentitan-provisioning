// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package se provides interfaces for working with different kinds of Secure
// Elements.
package se

import (
	"crypto/x509"
)

// Parameters for generating an RSA keypair.
type RSAParams struct {
	ModBits, Exp int
}

// Parameters for GenrateKeyPairAndCert().
type SigningParams struct {
	// The certificate to sign.
	Template *x509.Certificate
	// Parameters for generating the associated key pair; must be one
	// of RSAParams or elliptic.Curve.
	KeyParams any
}

// Parameters for EndorseCert().
type EndorseCertParams struct {
	// Key label. Used to identify the key in the HSM.
	KeyLabel string
	// Signature algorithm to use.
	SignatureAlgorithm x509.SignatureAlgorithm
}

// The return type of GenerateKeyPairAndCert().
type CertInfo struct {
	WrappedKey, Iv, Cert []byte
}

const (
	SymmetricKeyTypeRaw = iota
	SymmetricKeyTypeHashedOtLcToken
)

// Parameters for GenerateSymmetricKeys().
type SymmetricKeygenParams struct {
	UseHighSecuritySeed bool
	KeyType             uint
	SizeInBits          uint
	Sku                 string
	Diversifier         string
}

// SE is an interface representing a secure element, which may be implemented
// by various hardware modules under the hood.
//
// An SE provides privileged access to cryptographic operations using high-value
// assets, such as long-lived root secrets.
type SE interface {
	// Derives the transport secret for a device with the given ID, and wraps
	// it with the device class's global secret.
	DeriveAndWrapTransportSecret(deviceId []byte) ([]byte, error)

	// Generates and signs certificates with the given parent corresponding to the
	// arguments in certs.
	//
	// Returns: the certs along with their private keys, which will be wrapped with
	// Kg.
	//
	// The certs are returned in the order the parameters are provided. If an error
	// is returned, the returned slice will contain all certificates that were
	// successfully generated up until that point.
	GenerateKeyPairAndCert(caCert *x509.Certificate, params []SigningParams) ([]CertInfo, error)

	// Generates symmetric keys.
	//
	// These keys are generated via the HKDF mechanism and may be used as:
	//   - Wafer Authentication Secrets, or
	//   - Lifecycle Tokens.
	//
	// Returns: slice of AESKey objects.
	GenerateSymmetricKeys(params []*SymmetricKeygenParams) ([][]byte, error)

	// Endorses a certificate.
	//
	// This operation is used to sign a certificate with the SE's private key.
	// The certificate is provided in raw form, and the SE will return the
	// signed certificate in DER format.
	//
	// Returns: Raw signature in bytes.
	EndorseCert(tbs []byte, params EndorseCertParams) ([]byte, error)

	// GenerateRandom returns random data extracted from the HSM.
	GenerateRandom(length int) ([]byte, error)

	// VerifySession verifies that a session to the HSM for a given SKU is active
	VerifySession() error
}
