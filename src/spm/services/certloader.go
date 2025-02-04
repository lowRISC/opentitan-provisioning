// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package certloader loades the certificate template repository.
package certloader

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/cert/signer"
	"github.com/lowRISC/opentitan-provisioning/src/utils"

	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
)

var (
	TPMManufacturer = []int{2, 23, 133, 2, 1}
	TPMModel        = []int{2, 23, 133, 2, 2}
	TPMVersion      = []int{2, 23, 133, 2, 3}
	SubjectAltName  = []int{2, 5, 29, 17}
)

// KeyType is a type of key to generate.
type KeyType string

// KeyName represents signature algorithm.
type KeyName int

const (
	Secp256r1 KeyName = iota
	Secp384r1
	RSA2048
	RSA3072
	RSA4096
)

type Key struct {
	Type KeyType           `yaml:"type"`
	Size int               `yaml:"size"`
	Name KeyName           `yaml:"name"`
	Hash pbcommon.HashType `yaml:"hash"`
	Exp  []byte            `yaml:"exp"`
}

type SymmetricKey struct {
	Name string `yaml:"name"`
}

type PrivateKey struct {
	Name string `yaml:"name"`
}

// A SKUKey tracks information necessary to identify a specific signer
// template.
type SKUKey struct {
	SKU string
}

// String converts a SKUKey to a printable string.
func (t SKUKey) String() string {
	return fmt.Sprintf("%s", t.SKU)
}

type Loader struct{}

type CertificateSubjectAltName struct {
	Manufacturer string `yaml:"tpmManufacturer"`
	Model        string `yaml:"tpmModel"`
	Version      string `yaml:"tpmVersion"`
}

type CertificateConfig struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// New creates a new instance of the tpm certificate template builder.
func New() *Loader {
	return new(Loader)
}

// LoadTemplateFromFile returns a pre-defined certificate template.
func (l *Loader) LoadTemplateFromFile(configDir, filename string) (*x509.Certificate, error) {
	templateCert, err := utils.LoadCertFromFile(configDir, filename)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not load tpm certificate: %v", err)
	}
	return templateCert, nil
}

// UpdateIssuingCertificateURL returns a path to the issuing certificate URL
func UpdateIssuingCertificateURL(issuingCertificatePath, filenamePath string) (string, error) {
	_, filename := filepath.Split(filenamePath)
	dir, oldFilename := filepath.Split(issuingCertificatePath)
	if dir == "" {
		return "", status.Errorf(codes.Internal, "file name path %v is not legal, must contain '/'", oldFilename)
	}
	return dir + filename, nil
}

// BuildSubjectAltName implements an object identifier and value pair extension which
// can be used to build the TPM 2.0 Subject Alternative Extension as described
// on the TCG EK Credential Profile specification version 2.1.
func BuildSubjectAltName(certCfgSan CertificateSubjectAltName) (pkix.Extension, error) {
	type UTF8AttrVal struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}
	dirNames := []UTF8AttrVal{
		{
			Type:  TPMManufacturer,
			Value: certCfgSan.Manufacturer,
		},
		{
			Type:  TPMModel,
			Value: certCfgSan.Model,
		},
		{
			Type:  TPMVersion,
			Value: certCfgSan.Version,
		},
	}

	type UTF8RelativeDistinguishedNameSET []UTF8AttrVal
	type UTF8RDNSequence []UTF8RelativeDistinguishedNameSET
	rdnSequence := UTF8RDNSequence{}
	for _, atv := range dirNames {
		rdnSequence = append(rdnSequence, []UTF8AttrVal{atv})
	}

	var names []asn1.RawValue
	bytes, err := asn1.MarshalWithParams(rdnSequence, "explicit,tag:4")
	if err != nil {
		return pkix.Extension{}, err
	}
	names = append(names, asn1.RawValue{FullBytes: bytes})

	val, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       SubjectAltName,
		Critical: true,
		Value:    val,
	}, nil
}

// getTemplate returns Params struct from the certificate template.
// TODO: Load cert from file.
func getTemplate(repoKey SKUKey, key *Key) (*signer.Params, error) {
	epoch, err := time.Parse(time.RFC3339, "2022-01-01T00:00:00.000Z")
	if err != nil {
		return nil, err
	}

	subjectAltName, err := BuildSubjectAltName(
		CertificateSubjectAltName{
			Manufacturer: "id:4E544300",
			Model:        "NPCT75x",
			Version:      "id:00070002",
		})
	if err != nil {
		return nil, err
	}

	defaultCert := &signer.Params{
		Version:               3,
		SerialNumber:          []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		NotBefore:             epoch,
		NotAfter:              epoch.AddDate(20, 0, 0),
		Subject:               pkix.Name{},
		Issuer:                pkix.Name{},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectAltName:        subjectAltName,
		IssuingCertificateURL: []string{
			"https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NuvotonTPMRootCA0200.cer",
		},
		ExtKeyUsage: []asn1.ObjectIdentifier{
			{2, 23, 133, 8, 1},
		},
	}

	switch key.Name {
	case RSA2048:
		defaultCert.KeyUsage = x509.KeyUsageKeyEncipherment
	case RSA3072:
		defaultCert.KeyUsage = x509.KeyUsageKeyEncipherment
	case RSA4096:
		defaultCert.KeyUsage = x509.KeyUsageKeyEncipherment
	case Secp256r1:
		defaultCert.KeyUsage = x509.KeyUsageKeyAgreement
	case Secp384r1:
		defaultCert.KeyUsage = x509.KeyUsageKeyAgreement
	default:
	}

	return defaultCert, nil
}
