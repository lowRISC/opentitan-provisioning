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
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run generate_test_hpke_keys.go <output_directory>")
	}
	outDir := os.Args[1]

	// Generate ECDSA P-256 Key
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ecdsaPubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(outDir, "hpke_ecdsa.pub.der"), ecdsaPubBytes, 0644)
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
	err = os.WriteFile(filepath.Join(outDir, "hpke_mlkem.pub"), mlkemPubBytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
