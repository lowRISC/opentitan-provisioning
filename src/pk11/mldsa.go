// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package pk11

import (
	"crypto"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// TODO: Replace with official PKCS#11 constants when available.
const (
	CKM_MLDSA              = pkcs11.CKM_VENDOR_DEFINED + 0x100
	CKK_MLDSA              = pkcs11.CKK_VENDOR_DEFINED + 0x101
	CKM_MLDSA_KEY_PAIR_GEN = pkcs11.CKM_VENDOR_DEFINED + 0x102
)

// MldsaParameterSet specifies the ML-DSA parameter set.
type MldsaParameterSet int

const (
	MldsaParameterSetUnspecified MldsaParameterSet = 0
	MldsaParameterSet44          MldsaParameterSet = 1
	MldsaParameterSet65          MldsaParameterSet = 2
	MldsaParameterSet87          MldsaParameterSet = 3
)

// GenerateMLDSA generates an MLDSA key pair.
func (s *Session) GenerateMLDSA(params MldsaParameterSet, opts *KeyOptions) (KeyPair, error) {
	// TODO: Implement MLDSA key generation when HSM support is available.
	return KeyPair{}, fmt.Errorf("GenerateMLDSA not implemented")
}

// SignMLDSA signs a message using MLDSA.
func (k PrivateKey) SignMLDSA(message []byte) ([]byte, error) {
	return nil, fmt.Errorf("SignMLDSA not implemented")
}

// MLDSASigner implements crypto.Signer for MLDSA.
type MLDSASigner struct {
	PrivateKey
}

func (s MLDSASigner) Public() crypto.PublicKey {
	// TODO: Implement public key retrieval.
	return nil
}

func (s MLDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.PrivateKey.SignMLDSA(digest)
}
