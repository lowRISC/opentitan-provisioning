// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implements a Secure Provisioning Module CLI utility used to
// perform key management operations on the HSM.
package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	hsmType          = flag.Int64("hsm_type", 0, "The type of the hsm (0 - SoftHSM or 1 - TokenHSM); required")
	hsmSlot          = flag.Int("hsm_slot", 0, "The HSM slot number; required")
	genKG            = flag.Bool("gen_kg", false, "Generate KG; optional")
	genKCA           = flag.Bool("gen_kca", false, "Generate KCA; optional")
	loadHighSecKS    = flag.Bool("load_high_sec_ks", false, "Load high security KDF seed; optional")
	loadLowSecKS     = flag.Bool("load_low_sec_ks", false, "Load low security KDF seed; optional")
	forceKeygen      = flag.Bool("force_keygen", false, "Destroy existing keys and seeds before keygen; optional")
	caCertOutputPath = flag.String("ca_outfile", "", "CA output path; required when --gen_kca is set to true")
	highSecKS        = flag.String("high_sec_ks", "", "High security key seed; required when --load_high_sec_ks is set to true")
	lowSecKS         = flag.String("low_sec_ks", "", "Low security key seed; required when --load_low_sec_ks is set to true")
	version          = flag.Bool("version", false, "Print version information and exit")
)

const (
	kgName      = "KG"
	hsksName    = "HighSecKdfSeed"
	lsksName    = "LowSecKdfSeed"
	kcaPrivName = "KCAPriv"
	kcaPubName  = "KCAPub"
)

// initSession creates a new HSM instance with a single token session.
func initSession() (*se.HSM, error) {
	return se.NewHSM(se.HSMConfig{
		SOPath:      *hsmSOPath,
		SlotID:      *hsmSlot,
		HSMPassword: *hsmPW,
		NumSessions: 1,
		HSMType:     pk11.HSMType(*hsmType),
	})
}

// DestroyKeys destroys any existing key objects stored in the HSM token.
func DestroyKeys(session *pk11.Session) error {
	keys := []struct {
		class pk11.ClassAttribute
		label string
	}{
		{pk11.ClassSecretKey, kgName},
		{pk11.ClassSecretKey, hsksName},
		{pk11.ClassSecretKey, lsksName},
		{pk11.ClassPrivateKey, kcaPrivName},
		{pk11.ClassPublicKey, kcaPubName},
	}

	for _, k := range keys {
		if keyObj, err := session.FindKeyByLabel(k.class, k.label); err == nil {
			log.Printf("Destroying key: %q", k.label)
			if err := keyObj.Destroy(); err != nil {
				return fmt.Errorf("failed to destroy key with label %q: %v", k.label, err)
			}
		}
	}

	return nil
}

// GenerateKG generates a new KG key if there are no secret keys with a
// matching `kgName` label.
func GenerateKG(session *pk11.Session) error {
	// Skip keygen if there is a KG key available. In the future we can upate
	// this flow so that we update the key as opposed of returning early.
	if _, err := session.FindKeyByLabel(pk11.ClassSecretKey, kgName); err == nil {
		log.Printf("Key with label %q already exists.", kgName)
		return nil
	}

	kg, err := session.GenerateAES(256, &pk11.KeyOptions{
		Extractable: true,
		Token:       true,
	})
	if err != nil {
		return fmt.Errorf("failed to generate key, error: %v", err)
	}

	if err := kg.SetLabel(kgName); err != nil {
		return fmt.Errorf("failed to set key label %q, error: %v", kgName, err)
	}

	return nil
}

// loadKdfSeed loads a secret seed that may be used to derive symmetric keys
// from during the provisioning flow.
func loadKdfSeed(session *pk11.Session, seedName string, seed []byte) error {
	// Skip seed load if there is a seed with the same name already available.
	if _, err := session.FindKeyByLabel(pk11.ClassSecretKey, seedName); err == nil {
		log.Printf("KDF seed with label %q already exists.", seedName)
		return nil
	}

	// Load the seed into the HSM.
	kdfSeed, err := session.ImportKeyMaterial(seed, &pk11.KeyOptions{
		Extractable: false,
		Token:       true,
	})
	if err != nil {
		return fmt.Errorf("failed to load KDF seed, error: %v", err)
	}

	// Set a label name on the seed.
	if err := kdfSeed.SetLabel(seedName); err != nil {
		return fmt.Errorf("failed to set KDF seed label %q, error: %v", seedName, err)
	}

	return nil
}

// LoadHighSecKdfSeed loads a high security secret seed that may be used to
// derive symmetric keys from during the provisioning flow. This seed is
// expected to be rotated frequently.
func LoadHighSecKdfSeed(session *pk11.Session) error {
	if *highSecKS == "" {
		return errors.New("--high_sec_ks flag not set")
	}
	seed, _ := hex.DecodeString(*highSecKS)
	err := loadKdfSeed(session, hsksName, seed)
	if err != nil {
		return fmt.Errorf("failed to load high security KDF seed: %q", seed)
	}
	return nil
}

// LoadLowSecKdfSeed loads a low security secret seed that may be used to derive
// symmetric keys from during the provisioning flow. This seed is NOT expected
// to be rotated frequently.
func LoadLowSecKdfSeed(session *pk11.Session) error {
	if *lowSecKS == "" {
		return errors.New("--low_sec_ks flag not set")
	}
	seed, _ := hex.DecodeString(*lowSecKS)
	err := loadKdfSeed(session, lsksName, seed)
	if err != nil {
		return fmt.Errorf("failed to load low security KDF seed: %q", seed)
	}
	return nil
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

	if !*genKCA {
		log.Printf("Skipping %q keygen", kcaPrivName)
		return nil
	}

	if _, err := session.FindKeyByLabel(pk11.ClassPrivateKey, kcaPrivName); err == nil {
		log.Printf("Key with label %q already exists.", kcaPrivName)
		return nil
	}

	ca, err := session.GenerateECDSA(elliptic.P384(), &pk11.KeyOptions{
		Extractable: true,
		Token:       true,
	})
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %v", err)
	}

	if err := ca.PrivateKey.SetLabel(kcaPrivName); err != nil {
		return fmt.Errorf("failed to set key label %q, error: %v", kcaPrivName, err)
	}

	if err := ca.PublicKey.SetLabel(kcaPubName); err != nil {
		return fmt.Errorf("failed to set key label %q, error: %v", kcaPubName, err)
	}

	template, err := buildCACert(session)
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate template: %v", err)
	}

	privKey, err := ca.PrivateKey.Signer()
	if err != nil {
		return fmt.Errorf("failed to get signer from %q key: %v", kcaPrivName, err)
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

	for _, task := range []struct {
		label string
		run   bool
		f     se.CmdFunc
	}{
		{"Removing previous keys", *forceKeygen, DestroyKeys},
		{"Generating KG", *genKG, GenerateKG},
		{"Generating KCA", *genKCA, GenerateKCA},
		{"Loading high security KDF seed", *loadHighSecKS, LoadHighSecKdfSeed},
		{"Loading low security KDF seed", *loadLowSecKS, LoadLowSecKdfSeed},
	} {
		if !task.run {
			continue
		}
		log.Printf(task.label)
		if err := hsm.ExecuteCmd(task.f); err != nil {
			log.Fatalf("Failed task: %v", err)
		}
	}
}
