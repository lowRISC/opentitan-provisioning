// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// tbsgen is a tool to generate TBS certificates and assemble final certificates.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/lowRISC/opentitan-provisioning/src/spm/services/testutils/tbsgen"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "tbs":
		generateTBS()
	case "assemble":
		assembleCert()
	default:
		usage()
	}
}

func usage() {
	fmt.Println("Usage: tbsgen <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  tbs       Generate a TBS (To-Be-Signed) certificate from a CSR")
	fmt.Println("  assemble  Assemble a final certificate from TBS and a signature")
	os.Exit(1)
}

func generateTBS() {
	f := flag.NewFlagSet("tbs", flag.ExitOnError)
	csrPath := f.String("csr", "", "Path to the CSR (PEM or DER)")
	caCertPath := f.String("ca-cert", "", "Path to the CA certificate (optional, PEM or DER)")
	output := f.String("output", "", "Path to output the TBS DER file")
	days := f.Int("days", 7300, "Number of days the certificate is valid for. Use -1 for no expiry.")
	
	f.Parse(os.Args[2:])

	if *csrPath == "" || *output == "" {
		f.Usage()
		os.Exit(1)
	}

	csrBytes, err := ioutil.ReadFile(*csrPath)
	if err != nil {
		fmt.Printf("Failed to read CSR: %v\n", err)
		os.Exit(1)
	}
	csrDER := decodePEM(csrBytes, "CERTIFICATE REQUEST")

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		fmt.Printf("Failed to parse CSR: %v\n", err)
		os.Exit(1)
	}

	var caCert *x509.Certificate
	if *caCertPath != "" {
		caCertBytes, err := ioutil.ReadFile(*caCertPath)
		if err != nil {
			fmt.Printf("Failed to read CA cert: %v\n", err)
			os.Exit(1)
		}
		caCertDER := decodePEM(caCertBytes, "CERTIFICATE")
		caCert, err = x509.ParseCertificate(caCertDER)
		if err != nil {
			fmt.Printf("Failed to parse CA cert: %v\n", err)
			os.Exit(1)
		}
	}

	// For now, we assume if we are using this tool, we might want MLDSA patching.
	// We can detect it from the CSR public key OID or just always try to patch if it matches.
	// The current tbsgen library only patches if isMldsa is true.
	// Let's add a flag or detect it.
	
	// MLDSA-87 OID: 2.16.840.1.101.3.4.3.19
	isMldsa := false
	if csr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		// x509.ParseCertificateRequest might set Unknown for OIDs it doesn't know.
		// We should check the raw OID if possible, but for now let's just use a flag
		// or check if the signer is MLDSA in the script.
		isMldsa = true // Default to true if unknown, as this tool is mainly for MLDSA.
	}

	tbsDER, err := tbsgen.GenerateTBS(csr, caCert, *days, isMldsa)
	if err != nil {
		fmt.Printf("Failed to generate TBS: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(*output, tbsDER, 0644); err != nil {
		fmt.Printf("Failed to write output: %v\n", err)
		os.Exit(1)
	}
}

func assembleCert() {
	f := flag.NewFlagSet("assemble", flag.ExitOnError)
	tbsPath := f.String("tbs", "", "Path to the TBS DER file")
	sigPath := f.String("signature", "", "Path to the signature file (raw bytes)")
	output := f.String("output", "", "Path to output the final PEM certificate")

	f.Parse(os.Args[2:])

	if *tbsPath == "" || *sigPath == "" || *output == "" {
		f.Usage()
		os.Exit(1)
	}

	tbsDER, err := ioutil.ReadFile(*tbsPath)
	if err != nil {
		fmt.Printf("Failed to read TBS: %v\n", err)
		os.Exit(1)
	}

	sigBytes, err := ioutil.ReadFile(*sigPath)
	if err != nil {
		fmt.Printf("Failed to read signature: %v\n", err)
		os.Exit(1)
	}

	certDER, err := tbsgen.AssembleCertificate(tbsDER, sigBytes)
	if err != nil {
		fmt.Printf("Failed to assemble certificate: %v\n", err)
		os.Exit(1)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := ioutil.WriteFile(*output, certPEM, 0644); err != nil {
		fmt.Printf("Failed to write output: %v\n", err)
		os.Exit(1)
	}
}

func decodePEM(data []byte, expectedType string) []byte {
	block, _ := pem.Decode(data)
	if block == nil {
		return data
	}
	if expectedType != "" && !strings.Contains(block.Type, expectedType) {
		fmt.Printf("Warning: expected PEM type %q, got %q\n", expectedType, block.Type)
	}
	return block.Bytes
}
