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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

var (
	TPMManufacturer = []int{2, 23, 133, 2, 1}
	TPMModel        = []int{2, 23, 133, 2, 2}
	TPMVersion      = []int{2, 23, 133, 2, 3}
	SubjectAltName  = []int{2, 5, 29, 17}
)

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
func BuildSubjectAltName(certCfgSan skucfg.CertificateSubjectAltName) (pkix.Extension, error) {
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
