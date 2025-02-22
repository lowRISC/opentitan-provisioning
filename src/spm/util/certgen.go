// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main provides a command line tool to generate self signed
// certificates for testing purposes.
package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/cert/signer"
	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

var (
	hsmPW            = flag.String("hsm_pw", "", "The HSM's Password; required")
	hsmSOPath        = flag.String("hsm_so", "", "File path to the PCKS#11 .so library used to interface to the HSM; required")
	hsmSlot          = flag.Int("hsm_slot", 0, "The HSM slot number; required")
	caKeyLabel       = flag.String("ca_key_label", "", "CA HSM key label")
	caCertOutputPath = flag.String("ca_outfile", "", "CA output path; required when --gen_kca is set to true")
	version          = flag.Bool("version", false, "Print version information and exit")
)

// initSession creates a new HSM instance with a single token session.
func initSession() (*se.HSM, error) {
	return se.NewHSM(se.HSMConfig{
		SOPath:      *hsmSOPath,
		SlotID:      *hsmSlot,
		HSMPassword: *hsmPW,
		NumSessions: 1,
		HSMType:     pk11.HSMType(0),
	})
}

// buildCACert returns a root CA certificate template.
func buildCACert(session *pk11.Session) (*x509.Certificate, error) {
	serialNumber, err := session.GenerateRandom(10)
	if err != nil {
		return nil, fmt.Errorf("could not generate random serial number: %v", err)
	}

	// The serial number MUST be a positive integer.
	serialNumber[0] &= 0x7F
	// In case of leading zero set the msb to "1".
	if serialNumber[0] == 0 {
		serialNumber[0] = 1
	}

	certSN := big.NewInt(0)
	certSN.SetBytes(serialNumber)

	return &x509.Certificate{
		SerialNumber: certSN,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Organization:       []string{"OpenTitan"},
			OrganizationalUnit: []string{"Engineering"},
		},
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Organization:       []string{"OpenTitan"},
			OrganizationalUnit: []string{"Engineering"},
		},

		// Basic constraints with extension id: 2.5.29.19
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign,
		IssuingCertificateURL: nil,
	}, nil
}

// GenerateKCA generates an ECDSA key pair and and root self-signed CA
// certificate if there is no private key with matching `kcaPrivName`
// label. The self-signed certificate is exported to a `caCertOutputPath`
// location.
func GenerateKCA(session *pk11.Session) error {
	if *caCertOutputPath == "" {
		return errors.New("--ca_outfile flag not set")
	}

	caLabel := *caKeyLabel
	if caLabel == "" {
		return errors.New("--ca_key_label flag not set")
	}

	caObj, err := session.FindKeyByLabel(pk11.ClassPrivateKey, caLabel)
	if err != nil {
		return fmt.Errorf("failed to find key with label %q: %v", caLabel, err)
	}

	caUID, err := caObj.UID()
	if err != nil {
		return fmt.Errorf("failed to get key UID: %v", err)
	}

	ca, err := session.FindKeyPair(caUID)
	if err != nil {
		return fmt.Errorf("failed to find key pair with label %q: %v", caLabel, err)
	}

	template, err := buildCACert(session)
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate template: %v", err)
	}

	privKey, err := ca.PrivateKey.Signer()
	if err != nil {
		return fmt.Errorf("failed to get signer from %q key: %v", caLabel, err)
	}

	certBytes, err := signer.CreateCertificate(template, template, privKey.Public(), privKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate, %v", err)
	}

	err = os.WriteFile(*caCertOutputPath, certBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write cert to path %q: %v", *caCertOutputPath, err)
	}
	return nil
}

func main() {
	flag.Parse()

	// If the version flag true then print the version and exit,
	// otherwise only print the vertion to the to log
	utils.PrintVersion(*version)

	hsm, err := initSession()
	if err != nil {
		log.Fatalf("Failed to initialize HSM session, error: %v", err)
	}

	if err := hsm.ExecuteCmd(GenerateKCA); err != nil {
		log.Fatalf("Failed to execute GenerateKCA, error: %v", err)
	}
}
