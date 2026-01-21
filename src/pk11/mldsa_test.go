// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package test

import (
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
		})
	}
}
