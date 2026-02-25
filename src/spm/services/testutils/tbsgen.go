// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package tbsgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
)

// computeSKI calculates the Subject Key Identifier from raw SubjectPublicKeyInfo bytes.
func computeSKI(spki []byte) ([]byte, error) {
	if spki == nil {
		return nil, fmt.Errorf("SPKI bytes cannot be nil")
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validityStruct
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type validityStruct struct {
	NotBefore, NotAfter asn1.RawValue
}

// PatchTBSAlg patches the TBS certificate bytes to replace the ECDSA-SHA256 OID
// with MLDSA-87 OID.
func PatchTBSAlg(tbs []byte) ([]byte, error) {
	// MLDSA-87 OID: 2.16.840.1.101.3.4.3.19
	mldsaOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	var parsedTBS tbsCertificate
	if _, err := asn1.Unmarshal(tbs, &parsedTBS); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TBS: %v", err)
	}

	// Replace SignatureAlgorithm OID
	parsedTBS.SignatureAlgorithm.Algorithm = mldsaOID
	parsedTBS.SignatureAlgorithm.Parameters = asn1.RawValue{Tag: 0} // NULL or omitted? MLDSA usually omits parameters.
	// Actually, let's just set the OID.
	parsedTBS.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: mldsaOID,
	}

	parsedTBS.Raw = nil
	return asn1.Marshal(parsedTBS)
}

// GenerateTBS generates a To-Be-Signed (TBS) certificate from a CSR.
func GenerateTBS(csr *x509.CertificateRequest, caCert *x509.Certificate, days int, isMldsa bool) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	var notAfter time.Time
	if days == -1 {
		notAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	} else {
		notAfter = notBefore.Add(time.Duration(days) * 24 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:         true,
	}

	if caCert != nil {
		template.Issuer = caCert.Subject
		template.AuthorityKeyId = caCert.SubjectKeyId
	} else {
		template.Issuer = csr.Subject
	}

	// Subject Key Identifier
	template.SubjectKeyId, err = computeSKI(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to compute SKI: %v", err)
	}

	// We need a dummy signer to get the TBS.
	signerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy signer key: %v", err)
	}

	// Use a dummy public key for CreateCertificate because it doesn't support MLDSA.
	dummyPubPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dummy public key: %v", err)
	}
	dummyPub := dummyPubPriv.Public()

	var parent *x509.Certificate
	if caCert != nil {
		parent = &x509.Certificate{
			Subject:      caCert.Subject,
			RawSubject:   caCert.RawSubject,
			SubjectKeyId: caCert.SubjectKeyId,
			PublicKey:    signerPriv.Public(),
		}
	} else {
		parent = template
		// Trick CreateCertificate into self-signing with the dummy key.
		parent.PublicKey = signerPriv.Public()
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, dummyPub, signerPriv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}

	tbs := cert.RawTBSCertificate

	// Now surgically replace the Public Key and Algorithm OID if MLDSA.
	var parsedTBS tbsCertificate
	if _, err := asn1.Unmarshal(tbs, &parsedTBS); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TBS for patching: %v", err)
	}

	// Replace Public Key with the real one from the CSR.
	parsedTBS.PublicKey = asn1.RawValue{FullBytes: csr.RawSubjectPublicKeyInfo}

	if isMldsa {
		// MLDSA-87 OID: 2.16.840.1.101.3.4.3.19
		mldsaOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
		parsedTBS.SignatureAlgorithm = pkix.AlgorithmIdentifier{
			Algorithm: mldsaOID,
		}
	}

	parsedTBS.Raw = nil
	return asn1.Marshal(parsedTBS)
}

// AssembleCertificate assembles a final certificate from TBS and signature.
func AssembleCertificate(tbsDER []byte, sigBytes []byte) ([]byte, error) {
	// A certificate is a SEQUENCE of:
	// 1. TBSCertificate
	// 2. AlgorithmIdentifier
	// 3. BitString (Signature)

	// Extract AlgorithmIdentifier from TBS.
	// We use a minimal struct to unmarshal just what we need.
	var tbs struct {
		Raw          asn1.RawContent
		Version      int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber *big.Int
		Algorithm    pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(tbsDER, &tbs); err != nil {
		return nil, fmt.Errorf("failed to parse TBS: %v", err)
	}

	type rawCertificate struct {
		TBS            asn1.RawValue
		Algorithm      pkix.AlgorithmIdentifier
		SignatureValue asn1.BitString
	}

	cert := rawCertificate{
		TBS:            asn1.RawValue{FullBytes: tbsDER},
		Algorithm:      tbs.Algorithm,
		SignatureValue: asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8},
	}

	return asn1.Marshal(cert)
}

// buildTestTbsCert creates a To-Be-Signed (TBS) certificate for testing purposes.
// It takes an intermediate CA certificate. It generates a new key pair for the
// subject, creates a certificate, and returns the TBS part of it.
// The private key of the new certificate is also returned.
func buildTestTbsCert(label string, intermediateCACert *x509.Certificate, isMldsa bool) ([]byte, *ecdsa.PrivateKey, error) {
	// Generate a dummy ECDSA key to act as the signer.
	// We do this to satisfy x509.CreateCertificate, which doesn't support MLDSA keys.
	// The signature generated by this key will be invalid for the real CA, but we only
	// care about the TBS part, which doesn't contain the signature.
	signerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate dummy signer key: %v", err)
	}

	// Create a fake parent certificate that matches the signer key but mimics the real CA's identity.
	// This tricks CreateCertificate into generating a cert with the correct Issuer Name/ID but signed by our dummy key.
	// This bypasses the check where signerPriv must match intermediateCACert.PublicKey.
	fakeParent := &x509.Certificate{
		Subject:      intermediateCACert.Subject,
		RawSubject:   intermediateCACert.RawSubject,
		SubjectKeyId: intermediateCACert.SubjectKeyId,
		PublicKey:    signerPriv.Public(),
	}

	// Generate a new public key for the DUT.
	dutKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	pubKey := dutKey.PublicKey

	spki, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return nil, nil, err
	}
	ski, err := computeSKI(spki)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{label + " Test Certificate"},
			CommonName:   label,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Issuer:                intermediateCACert.Subject,
		AuthorityKeyId:        intermediateCACert.SubjectKeyId,
		SubjectKeyId:          ski,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, fakeParent, &pubKey, signerPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	tbs := cert.RawTBSCertificate
	if isMldsa {
		tbs, err = PatchTBSAlg(tbs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to patch TBS for MLDSA: %v", err)
		}
	}

	return tbs, dutKey, nil
}

// BuildTestTBSCerts generates a set of TBS certificates for a given SKU.
// It returns a map of TBS certificates and a map of the corresponding private keys.
func BuildTestTBSCerts(mgr *skumgr.Manager, skuName string, certLabels []string) (map[string][]byte, map[string]*ecdsa.PrivateKey, error) {
	sku, err := mgr.LoadSku(skuName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load SKU %q: %w", skuName, err)
	}

	tbsCerts := make(map[string][]byte)
	privKeys := make(map[string]*ecdsa.PrivateKey)
	for _, kl := range certLabels {
		var label string
		isMldsa := false
		if kl == "UDS" {
			label = "SigningKey/Dice/v0"
		} else if kl == "UDS_MLDSA" {
			label = "SigningKey/Dice/Mldsa/v0"
			isMldsa = true
		} else if strings.HasPrefix(kl, "EXT_MLDSA_") {
			label = "SigningKey/Ext/Mldsa/v0"
			isMldsa = true
		} else if strings.HasPrefix(kl, "EXT_") {
			label = "SigningKey/Ext/v0"
		} else {
			return nil, nil, fmt.Errorf("invalid certificate label %q", kl)
		}

		issuerCert, ok := sku.Certs[label]
		if !ok {
			return nil, nil, fmt.Errorf("issuer certificate %q not found for SKU %q", label, skuName)
		}

		tbs, priv, err := buildTestTbsCert(label, issuerCert, isMldsa)
		if err != nil {
			return nil, nil, err
		}
		tbsCerts[kl] = tbs
		privKeys[kl] = priv
	}

	return tbsCerts, privKeys, nil
}
