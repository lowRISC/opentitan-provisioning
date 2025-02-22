// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/tools/bazel"

	"github.com/lowRISC/opentitan-provisioning/src/cert/signer"
	"github.com/lowRISC/opentitan-provisioning/src/cert/templates/tpm"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/certloader"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

const (
	devicePubKeyPath = "src/cert/templates/testdata/tpm_rsa_device_key.pub.pem"
	deviceCertPath   = "src/cert/templates/testdata/tpm_rsa_device_cert.pem"
	caPrivKeyPath    = "src/cert/templates/testdata/tpm_rsa_ca_key.pem"
	caCertPath       = "src/cert/templates/testdata/tpm_rsa_ca_cert.pem"
)

func readFile(t *testing.T, filename string) []byte {
	t.Helper()
	filename, err := bazel.Runfile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("unable to load file: %q, error: %v", filename, err)
	}
	return data
}

func loadCertFromFile(t *testing.T, filename string) (*x509.Certificate, []byte) {
	t.Helper()
	cert := readFile(t, filename)
	pemCert, _ := pem.Decode(cert)
	certObj, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		t.Fatalf("unable to parse certificate, error: %v", err)
	}
	return certObj, pemCert.Bytes
}

func loadPKCS1PrivateKeyFromFile(t *testing.T, filename string) *rsa.PrivateKey {
	t.Helper()
	priv := readFile(t, filename)
	pemKey, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		t.Fatalf("unable to parse private key, error: %v", err)
	}
	return key
}

func loadPKIXPublicKeyFromFile(t *testing.T, filename string) *rsa.PublicKey {
	t.Helper()
	pub := readFile(t, filename)
	pemKey, _ := pem.Decode(pub)

	rawKey, err := x509.ParsePKIXPublicKey(pemKey.Bytes)
	if err != nil {
		t.Fatalf("unable to parse public key, error: %v", err)
	}
	return rawKey.(*rsa.PublicKey)
}

func TestCertFormat(t *testing.T) {
	notBefore, err := time.Parse(time.RFC3339, "2021-12-12T13:38:26.371Z")
	if err != nil {
		t.Fatalf("unable to parse no_before date string, err: %v", err)
	}

	notAfter, err := time.Parse(time.RFC3339, "2022-12-12T13:38:26.371Z")
	if err != nil {
		t.Fatalf("unable to parse no_after date string, error: %v", err)
	}

	subjectAltName, err := certloader.BuildSubjectAltName(
		skucfg.CertificateSubjectAltName{
			Manufacturer: "id:4E544300",
			Model:        "NPCT75x",
			Version:      "id:00070002",
		})
	if err != nil {
		t.Fatalf("unable to build subject alteraive name, error: %v", err)
	}

	b := tpm.New()
	template, err := b.Build(&signer.Params{
		SerialNumber: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Organization:       []string{"OpenTitan"},
			OrganizationalUnit: []string{"Engineering"},
		},
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Organization:       []string{"OpenTitan"},
			OrganizationalUnit: []string{"Engineering"},
			CommonName:         "OpenTitan TPM EK",
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		SubjectAltName: subjectAltName,
	})
	if err != nil {
		t.Fatalf("unable to generate certificate template, error: %v", err)
	}

	devicePub := loadPKIXPublicKeyFromFile(t, devicePubKeyPath)
	caPriv := loadPKCS1PrivateKeyFromFile(t, caPrivKeyPath)
	caCert, _ := loadCertFromFile(t, caCertPath)
	gotCert, err := signer.CreateCertificate(template, caCert, devicePub, caPriv)
	if err != nil {
		t.Fatalf("failed to sign certificate, error: %v", err)
	}

	_, expCert := loadCertFromFile(t, deviceCertPath)
	if ok := bytes.Equal(expCert, gotCert); !ok {
		gotCertPem := utils.BlobToPEMString(gotCert)
		t.Errorf("unexpected certificate result. Please inspect results and update the test dependencies. Got:\n%s\n", gotCertPem)
	}
}
