// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	ts "github.com/lowRISC/opentitan-provisioning/src/pk11/test_support"
)

func TestMLDSA(t *testing.T) {
	tests := []struct {
		params pk11.MldsaParameterSet
	}{
		{pk11.MldsaParameterSet44},
		{pk11.MldsaParameterSet65},
		{pk11.MldsaParameterSet87},
	}

	s := ts.GetSession(t)
	ts.Check(t, s.Login(pk11.NormalUser, ts.UserPin))

	for _, test := range tests {
		name := fmt.Sprintf("MLDSA-%d", test.params)
		t.Run(name, func(t *testing.T) {
			kp, err := s.GenerateMLDSA(test.params, nil)
			if err != nil {
				t.Fatalf("GenerateMLDSA failed: %v", err)
			}

			message := []byte("Hello MLDSA")
			sig, err := kp.PrivateKey.SignMLDSA(message)
			if err != nil {
				t.Fatalf("SignMLDSA failed: %v", err)
			}

			if len(sig) == 0 {
				t.Fatal("generated signature is empty")
			}
			t.Logf("Signature length: %d", len(sig))

			if err := kp.PublicKey.VerifyMLDSA(message, sig); err != nil {
				t.Fatalf("VerifyMLDSA failed: %v", err)
			}

			// Test ExportKey on the public key.
			exportedKey, err := kp.PublicKey.ExportKey()
			if err != nil {
				t.Fatalf("ExportKey failed: %v", err)
			}
			mldsaPub, ok := exportedKey.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("ExportKey returned unexpected type: %T", exportedKey)
			}

			// Verify the signature with Go's standard library crypto/mldsa.
			if err := mldsa.Verify(mldsaPub, message, sig, nil); err != nil {
				t.Fatalf("crypto/mldsa.Verify failed on PKCS#11 signature: %v", err)
			}

			// Test crypto.Signer interface.
			signer, err := kp.PrivateKey.Signer()
			if err != nil {
				t.Fatalf("Signer() failed: %v", err)
			}

			pub := signer.Public()
			if pub == nil {
				t.Fatal("signer.Public() returned nil")
			}
			signerPub, ok := pub.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("signer.Public() returned unexpected type: %T", pub)
			}
			if !signerPub.Equal(mldsaPub) {
				t.Fatal("signer.Public() does not match exported public key")
			}

			// Sign via crypto.Signer.
			signerSig, err := signer.Sign(rand.Reader, message, nil)
			if err != nil {
				t.Fatalf("signer.Sign() failed: %v", err)
			}
			if err := mldsa.Verify(mldsaPub, message, signerSig, nil); err != nil {
				t.Fatalf("crypto/mldsa.Verify failed on crypto.Signer signature: %v", err)
			}
		})
	}
}
