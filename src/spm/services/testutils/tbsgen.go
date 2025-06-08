// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package tbsgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
)

// computeSKI calculates the Subject Key Identifier for a public key.
func computeSKI(pubKey crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

// buildTestTbsCert creates a To-Be-Signed (TBS) certificate for testing purposes.
// It takes an intermediate CA certificate. It generates a new key pair for the
// subject, creates a certificate, and returns the TBS part of it.
// The public key of the new certificate is also returned.
func buildTestTbsCert(session *pk11.Session, label string, intermediateCACert *x509.Certificate) ([]byte, crypto.PublicKey, error) {
	// Get the private key object.
	keyID, err := se.GetKeyIDByLabel(session, pk11.ClassPrivateKey, label)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get key ID by label %q: %v", label, err)
	}

	key, err := session.FindPrivateKey(keyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find key object %q: %v", keyID, err)
	}

	privKey, err := key.Signer()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signer: %v", err)
	}

	// Generate a new public key outside the HSM.
	dutKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %v", err)
	}
	pubKey := dutKey.PublicKey

	ski, err := computeSKI(&pubKey)
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
			Organization: []string{"Test Certificate"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		Issuer:                intermediateCACert.Subject,
		AuthorityKeyId:        intermediateCACert.SubjectKeyId,
		SubjectKeyId:          ski,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, intermediateCACert, &pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert.RawTBSCertificate, &pubKey, nil
}

// BuildTestTBSCerts generates a set of TBS certificates for a given SKU.
// It returns a map of TBS certificates and a map of the corresponding public keys.
func BuildTestTBSCerts(opts skumgr.Options, skuName string, certLabels []string) (map[string][]byte, map[string]crypto.PublicKey, error) {
	mgr := skumgr.NewManager(opts)
	sku, err := mgr.LoadSku(skuName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load SKU %q: %w", skuName, err)
	}

	tbsCerts := make(map[string][]byte)
	pubKeys := make(map[string]crypto.PublicKey)
	for _, label := range certLabels {
		issuerCert, ok := sku.Certs[label]
		if !ok {
			return nil, nil, fmt.Errorf("issuer certificate %q not found for SKU %q", label, skuName)
		}
		privKeyLabel, err := sku.Config.GetUnsafeAttribute(label)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get private key label for %q: %v", label, err)
		}
		hsm := sku.SeHandle.(*se.HSM)
		if err := hsm.ExecuteCmd(func(session *pk11.Session) error {
			tbs, pub, err := buildTestTbsCert(session, privKeyLabel, issuerCert)
			if err != nil {
				return err
			}
			tbsCerts[label] = tbs
			pubKeys[label] = pub
			return nil
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to generate TBS certificate: %w", err)
		}
	}

	return tbsCerts, pubKeys, nil
}
