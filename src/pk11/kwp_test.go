// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	kwp "github.com/google/tink/go/kwp/subtle"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	ts "github.com/lowRISC/opentitan-provisioning/src/pk11/test_support"
)

func TestAESKWPWrapPrivate(t *testing.T) {
	tests := []uint{128, 256}

	s := ts.GetSession(t)
	ts.Check(t, s.Login(pk11.NormalUser, ts.UserPin))

	for _, test := range tests {
		name := fmt.Sprintf("%v", test)
		t.Run(name, func(t *testing.T) {
			// This does not need to be secure randomness.
			key := make([]byte, test/8)
			rand.Read(key)

			ki, err := s.ImportKey(pk11.AESKey(key), nil)
			ts.Check(t, err)
			ko := ki.(pk11.SecretKey)
			kp, err := s.GenerateECDSA(elliptic.P256(), &pk11.KeyOptions{Extractable: true})
			ts.Check(t, err)
			pubi, err := kp.PublicKey.ExportKey()
			ts.Check(t, err)
			pub := pubi.(*ecdsa.PublicKey)
			wrap, err := ko.WrapAESKWP(kp.PrivateKey)
			ts.Check(t, err)

			kwp, err := kwp.NewKWP(key)
			ts.Check(t, err)
			unwrap, err := kwp.Unwrap(wrap)
			ts.Check(t, err)

			privi, err := x509.ParsePKCS8PrivateKey(unwrap)
			ts.Check(t, err)
			priv := privi.(*ecdsa.PrivateKey)

			if !pub.Equal(&priv.PublicKey) {
				t.Fatal("public key mismatch:", cmp.Diff(pub, &priv.PublicKey))
			}
		})
	}
}

func TestAESKWPWrapSecret(t *testing.T) {
	tests := []uint{128, 256}

	s := ts.GetSession(t)
	ts.Check(t, s.Login(pk11.NormalUser, ts.UserPin))

	for _, test := range tests {
		name := fmt.Sprintf("%v", test)
		t.Run(name, func(t *testing.T) {
			// This does not need to be secure randomness.
			key := make([]byte, test/8)
			rand.Read(key)

			ki, err := s.ImportKey(pk11.AESKey(key), nil)
			ts.Check(t, err)
			ko := ki.(pk11.SecretKey)

			wo, err := s.GenerateAES(256, &pk11.KeyOptions{Extractable: true})
			ts.Check(t, err)
			wi, err := wo.ExportKey()
			ts.Check(t, err)
			wrapped := wi.(pk11.AESKey)

			wrap, err := ko.WrapAESKWP(wo)
			ts.Check(t, err)

			kwp, err := kwp.NewKWP(key)
			ts.Check(t, err)
			unwrap, err := kwp.Unwrap(wrap)
			ts.Check(t, err)

			if !bytes.Equal(wrapped, unwrap) {
				t.Fatalf("unwrap mismatch: %x %x", wrapped, unwrap)
			}
		})
	}
}
