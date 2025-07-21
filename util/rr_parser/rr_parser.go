// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/lowRISC/opentitan-provisioning/src/ate"
	"github.com/lowRISC/opentitan-provisioning/src/utils"

	dipb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	rrpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	proxybufferpb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

const LineLimit = 100

type cert struct {
	id   string
	data string
}

type certs struct {
	diceICA  []cert
	extICA   []cert
	diceLeaf []cert
	extLeafs []cert
}

func processPersoBlob(persoBlobBytes []byte, diceLeaf string) (*certs, error) {
	certs := &certs{}

	persoBlob, err := ate.UnpackPersoBlob(persoBlobBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack perso blob: %v", err)
	}

	for _, c := range persoBlob.X509Certs {
		log.Printf("Found cert: %s\n", c.KeyLabel)
		kID := strings.ReplaceAll(c.KeyLabel, " ", "_")
		if kID == "" {
			return nil, fmt.Errorf("empty key label in certificate")
		}

		cert := cert{
			id:   kID,
			data: utils.DERCertToPEMString(c.Cert),
		}

		switch c.KeyLabel {
		case "UDS":
			if diceLeaf == "UDS" {
				certs.diceLeaf = append(certs.diceLeaf, cert)
			} else {
				certs.diceICA = append(certs.diceICA, cert)
			}
		case "CDI_0":
			if diceLeaf == "UDS" {
				return nil, fmt.Errorf("unexpected DICE leaf '%s' for cert '%s'", diceLeaf, c.KeyLabel)
			}

			if diceLeaf == "CDI_0" {
				certs.diceLeaf = append(certs.diceLeaf, cert)
			} else {
				certs.diceICA = append(certs.diceICA, cert)
			}
		case "CDI_1":
			if diceLeaf == "CDI_1" {
				certs.diceLeaf = append(certs.diceLeaf, cert)
			} else {
				return nil, fmt.Errorf("unexpected DICE leaf '%s' for cert '%s'", diceLeaf, c.KeyLabel)
			}
		default:
			// If the certificate key label  is not one of the expected DICE certificates,
			// assume it's an external certificate.
			certs.extLeafs = append(certs.extLeafs, cert)
		}
	}

	for _, s := range persoBlob.Seeds {
		typeStr := "Unknown"
		switch s.Type {
		case ate.PersoObjectTypeDevSeed:
			typeStr = "Dev Seed"
		case ate.PersoObjectTypeGenericSeed:
			typeStr = "Generic Seed"
		}
		log.Printf("Seed type: %s, value: \n%s\n", typeStr, hex.Dump(s.Raw))
	}

	for _, c := range persoBlob.CwtCerts {
		log.Printf("Found CWT cert: %s, data: \n%s\n", c.KeyLabel, hex.Dump(c.Cert))
	}

	return certs, nil
}

func parseRegistryRecord(rr *rrpb.RegistryRecord, diceLeaf string) (*certs, error) {
	// Parse device data from from the registry record.
	deviceData := &dipb.DeviceData{}
	proto.Unmarshal(rr.Data, deviceData)

	// Print each field of the registry record.
	log.Println(strings.Repeat("-", LineLimit))
	log.Println("Registry Record: ")
	log.Println(strings.Repeat("-", LineLimit))
	log.Printf("SKU:        %s\n", rr.Sku)
	log.Printf("Version:    %d\n", rr.Version)
	log.Printf("Device ID:  %s\n", rr.DeviceId)
	log.Println(strings.Repeat("-", LineLimit))
	log.Printf("Perso Firmware Hash:  %032x\n", deviceData.PersoFwSha256Hash)
	log.Printf("LC State:             %s\n", deviceData.DeviceLifeCycle)
	log.Printf("Wrapped RMA Token:\n%s\n", hex.Dump(deviceData.WrappedRmaUnlockToken))
	log.Println(strings.Repeat("-", LineLimit))
	log.Printf("Num Perso TLV Objects:  %d\n", deviceData.NumPersoTlvObjects)

	certs, err := processPersoBlob(deviceData.PersoTlvData, diceLeaf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse perso blob: %v", err)
	}

	log.Println(strings.Repeat("-", LineLimit))
	log.Println("Record endorsement (decode at: https://lapo.it/asn1js/): ")
	log.Printf("AuthPubkey    (ASN.1 DER): %x\n", rr.AuthPubkey)
	log.Printf("AuthSignature (ASN.1 DER): %x\n", rr.AuthSignature)

	return certs, nil
}

func parseFlags() (string, string, string, string, string) {
	diceCertLeaf := flag.String("dice-leaf", "", "DICE cert leaf: UDS, CDI_0 or CDI_1. Required.")
	diceICA := flag.String("dice-ica", "", "Path to the DICE ICA certificate file. Required.")
	extICA := flag.String("ext-ica", "", "Path to the external ICA certificate file. Optional.")
	rootCA := flag.String("root-cert", "", "Path to a root certificate file. May be specified multiple times.")
	rrJSONPath := flag.String("rr-json", "", "Path to the JSON registry record file. Required.")

	flag.Parse()

	if *rrJSONPath == "" {
		log.Fatal("Usage: go run rr_parser.go -rr-json <JSON registry record> [-root-cert <path/to/cert.pem> ...]")
	}

	if *diceCertLeaf == "" || *diceICA == "" || *rootCA == "" {
		log.Fatalf("Error: -dice-leaf, -dice-ica, and -root-cert flags are required.")
	}

	switch *diceCertLeaf {
	case "UDS", "CDI_0", "CDI_1":
	default:
		log.Fatalf("Error: Invalid DICE cert leaf '%s'. Must be one of: UDS, CDI_0, or CDI_1.", *diceCertLeaf)
	}

	return *diceCertLeaf, *diceICA, *extICA, *rootCA, *rrJSONPath
}

func parseRR(rrJSONPath string) (*rrpb.RegistryRecord, error) {
	rrBytes, err := utils.ReadFile(rrJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read registry record file: %v", err)
	}

	var rr proxybufferpb.DeviceRegistrationRequest
	if err := json.Unmarshal(rrBytes, &rr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registry record JSON: %v", err)
	}

	return rr.Record, nil
}

func writeFile(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing file %q: %v", path, err)
	}
	if err := utils.WriteFile(path, data, 0666); err != nil {
		return fmt.Errorf("failed to write file %q: %v", path, err)
	}
	return nil
}

func verifyCertificate(rootCA, intermediateCAs, leafCert string, ignore_critical bool) error {
	args := []string{"verify"}
	if ignore_critical {
		args = append(args, "-ignore_critical")
	}
	args = append(args, "-CAfile", rootCA, "-untrusted", intermediateCAs, leafCert)

	cmd := exec.Command("openssl", args...)
	fmt.Println("Running command:", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to verify certificate: %v\n%s", err, output)
	}
	return nil
}

func main() {
	diceCertLeaf, diceICA, extICA, rootCA, rrJSONPath := parseFlags()

	baseDir := filepath.Dir(rrJSONPath)
	filename := strings.TrimSuffix(filepath.Base(rrJSONPath), filepath.Ext(rrJSONPath))

	logFilename := filepath.Join(baseDir, filename+"-rr_parser.log")
	logFile, err := os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file %q: %v", logFilename, err)
	}
	defer logFile.Close()
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(multiWriter)

	log.Printf("Parsing registry record from %s", rrJSONPath)

	rr, err := parseRR(rrJSONPath)
	if err != nil {
		log.Fatalf("Failed to parse registry record: %v", err)
	}

	certs, err := parseRegistryRecord(rr, diceCertLeaf)
	if err != nil {
		log.Fatalf("Error parsing registry record: %v", err)
	}

	diceICABytes, err := utils.ReadFile(diceICA)
	if err != nil {
		log.Fatalf("Failed to read DICE ICA certificate file: %v", err)
	}
	certs.diceICA = append(certs.diceICA, cert{id: diceICA, data: string(diceICABytes)})

	if extICA != "" {
		extICABytes, err := utils.ReadFile(extICA)
		if err != nil {
			log.Fatalf("Failed to read external ICA certificate file: %v", err)
		}
		certs.extICA = append(certs.extICA, cert{id: extICA, data: string(extICABytes)})
	}

	var diceICACerts strings.Builder
	for _, cert := range certs.diceICA {
		diceICACerts.WriteString(cert.data)
	}
	diceICAFilename := filepath.Join(baseDir, filename+"-dice-ica.pem")
	log.Printf("Writing DICE ICA certificates to %s", diceICAFilename)
	if err := writeFile(diceICAFilename, []byte(diceICACerts.String())); err != nil {
		log.Fatalf("failed to write DICE ICA certificates: %v", err)
	}

	var extICACerts strings.Builder
	for _, cert := range certs.extICA {
		extICACerts.WriteString(cert.data)
	}
	extICAFilename := filepath.Join(baseDir, filename+"-ext-ica.pem")
	extICAbytes := []byte(extICACerts.String())
	if len(extICAbytes) > 0 {
		log.Printf("Writing external ICA certificates to %s", extICAFilename)
		if err := writeFile(extICAFilename, extICAbytes); err != nil {
			log.Fatalf("failed to write external ICA certificates: %v", err)
		}
	}

	for _, cert := range certs.diceLeaf {
		diceLeafFilename := filepath.Join(baseDir, filename+"-dice-leaf-"+cert.id+".pem")
		log.Printf("Writing DICE leaf certificate to %s", diceLeafFilename)
		if err := writeFile(diceLeafFilename, []byte(cert.data)); err != nil {
			log.Fatalf("failed to write DICE leaf certificate: %v", err)
		}
		if err := verifyCertificate(rootCA, diceICAFilename, diceLeafFilename, true); err != nil {
			log.Fatalf("failed to verify DICE leaf certificate: %v", err)
		}
	}

	for _, cert := range certs.extLeafs {
		extLeafFilename := filepath.Join(baseDir, filename+"-ext-leaf-"+cert.id+".pem")
		log.Printf("Writing ext leaf certificate to %s", extLeafFilename)
		if err := writeFile(extLeafFilename, []byte(cert.data)); err != nil {
			log.Fatalf("failed to write external leaf certificate: %v", err)
		}
		if err := verifyCertificate(rootCA, extICAFilename, extLeafFilename, false); err != nil {
			log.Fatalf("failed to verify external leaf certificate: %v", err)
		}
	}

	log.Println("All certificates processed and verified successfully.")
}
