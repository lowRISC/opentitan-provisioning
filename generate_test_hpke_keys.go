// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"log"
	"os"
)

func main() {
	// Generate ECDSA P-256 Key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ecdsaPubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("config/spm/sku/test_hpke/ca/hpke_ecdsa.pub.der", ecdsaPubBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}

	// Generate ML-KEM-768 Key
	mlkemPriv, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}
	mlkemPub := mlkemPriv.EncapsulationKey()
	mlkemPubBytes := mlkemPub.Bytes()
	err = os.WriteFile("config/spm/sku/test_hpke/ca/hpke_mlkem.pub", mlkemPubBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
