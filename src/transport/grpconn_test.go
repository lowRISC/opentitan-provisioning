// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package grpconn

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestApplyMLKEMConfig(t *testing.T) {
	tests := []struct {
		name           string
		enableMLKEM    bool
		expectMinVer   uint16
		expectCurve    bool
	}{
		{
			name:           "Disabled",
			enableMLKEM:    false,
			expectMinVer:   0, // Default 0 means allow lower versions (implementation dependent, usually 1.0 or 1.2)
			expectCurve:    false,
		},
		{
			name:           "Enabled",
			enableMLKEM:    true,
			expectMinVer:   tls.VersionTLS13,
			expectCurve:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{EnableMLKEMTLS: tc.enableMLKEM}
			tlsConfig := &tls.Config{}
			
			cfg.applyMLKEMConfig(tlsConfig)

			if tc.enableMLKEM {
				if tlsConfig.MinVersion != tc.expectMinVer {
					t.Errorf("Expected MinVersion %v, got %v", tc.expectMinVer, tlsConfig.MinVersion)
				}

				found := false
				for _, curve := range tlsConfig.CurvePreferences {
					if curve == tls.X25519MLKEM768 {
						found = true
						break
					}
				}
				if !tc.expectCurve {
					t.Errorf("Expected MLKEM curve to be present")
				} else if !found {
					t.Errorf("Expected MLKEM curve to be present")
				}
			} else {
				// When disabled, we expect no changes to the default (empty) tlsConfig
				if tlsConfig.MinVersion != 0 {
					t.Errorf("Expected MinVersion 0, got %v", tlsConfig.MinVersion)
				}
				if len(tlsConfig.CurvePreferences) > 0 {
					t.Errorf("Expected no CurvePreferences, got %v", tlsConfig.CurvePreferences)
				}
			}
		})
	}
}

func TestApplyMLDSAConfig(t *testing.T) {
	tests := []struct {
		name            string
		enableMLDSA     bool
		expectMinVer    uint16
		expectVerifySet bool
	}{
		{
			name:            "Disabled",
			enableMLDSA:     false,
			expectMinVer:    0,
			expectVerifySet: false,
		},
		{
			name:            "Enabled",
			enableMLDSA:     true,
			expectMinVer:    tls.VersionTLS13,
			expectVerifySet: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{EnableMLDSATLS: tc.enableMLDSA}
			tlsConfig := &tls.Config{}

			cfg.applyMLDSAConfig(tlsConfig)

			if tc.enableMLDSA {
				if tlsConfig.MinVersion != tc.expectMinVer {
					t.Errorf("Expected MinVersion %v, got %v", tc.expectMinVer, tlsConfig.MinVersion)
				}
				if (tlsConfig.VerifyPeerCertificate != nil) != tc.expectVerifySet {
					t.Errorf("Expected VerifyPeerCertificate to be set")
				}
			} else {
				if tlsConfig.MinVersion != 0 {
					t.Errorf("Expected MinVersion 0, got %v", tlsConfig.MinVersion)
				}
				if tlsConfig.VerifyPeerCertificate != nil {
					t.Errorf("Expected VerifyPeerCertificate to be nil, got %v", tlsConfig.VerifyPeerCertificate)
				}
			}
		})
	}
}

func generateTestMLDSACert(t *testing.T, params mldsa.Parameters, cn string, isCA bool, parentCert *x509.Certificate, parentPriv any) (tls.Certificate, *x509.Certificate, *mldsa.PrivateKey) {
	t.Helper()
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	signerCert := template
	signerKey := any(priv)
	if parentCert != nil {
		signerCert = parentCert
		signerKey = parentPriv
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{"localhost", cn}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, priv.PublicKey(), signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return tlsCert, parsed, priv
}

func generateTestRSACert(t *testing.T, cn string, isCA bool, parentCert *x509.Certificate, parentPriv any) (tls.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey (RSA): %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	signerCert := template
	signerKey := any(priv)
	if parentCert != nil {
		signerCert = parentCert
		signerKey = parentPriv
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.DNSNames = []string{"localhost", cn}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &priv.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return tlsCert, parsed, priv
}

func TestVerifyMLDSAPeerCertificate(t *testing.T) {
	// ML-DSA CA
	_, caMLDSACert, caMLDSAPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "MLDSA-Root-CA", true, nil, nil)
	// RSA CA
	_, caRSACert, caRSAPriv := generateTestRSACert(t, "RSA-Root-CA", true, nil, nil)

	// Valid ML-DSA certificates (44, 65, 87) issued by ML-DSA CA
	_, leaf44, _ := generateTestMLDSACert(t, mldsa.MLDSA44(), "leaf-44", false, caMLDSACert, caMLDSAPriv)
	_, leaf65, _ := generateTestMLDSACert(t, mldsa.MLDSA65(), "leaf-65", false, caMLDSACert, caMLDSAPriv)
	_, leaf87, _ := generateTestMLDSACert(t, mldsa.MLDSA87(), "leaf-87", false, caMLDSACert, caMLDSAPriv)

	// Invalid certificates:
	// 1. RSA leaf signed by RSA CA
	_, leafRSA, _ := generateTestRSACert(t, "leaf-rsa", false, caRSACert, caRSAPriv)
	// 2. ML-DSA leaf signed by RSA CA (signature is RSA)
	priv44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "mldsa-signed-by-rsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derMLDSAbyRSA, err := x509.CreateCertificate(rand.Reader, tmpl, caRSACert, priv44.PublicKey(), caRSAPriv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leafMLDSAbyRSA, err := x509.ParseCertificate(derMLDSAbyRSA)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	tests := []struct {
		name           string
		rawCerts       [][]byte
		verifiedChains [][]*x509.Certificate
		expectErr      bool
	}{
		{
			name:           "Valid MLDSA-44 Chain",
			rawCerts:       [][]byte{leaf44.Raw},
			verifiedChains: [][]*x509.Certificate{{leaf44, caMLDSACert}},
			expectErr:      false,
		},
		{
			name:           "Valid MLDSA-65 Chain",
			rawCerts:       [][]byte{leaf65.Raw},
			verifiedChains: [][]*x509.Certificate{{leaf65, caMLDSACert}},
			expectErr:      false,
		},
		{
			name:           "Valid MLDSA-87 Chain",
			rawCerts:       [][]byte{leaf87.Raw},
			verifiedChains: [][]*x509.Certificate{{leaf87, caMLDSACert}},
			expectErr:      false,
		},
		{
			name:           "Valid Raw MLDSA-65 without VerifiedChains",
			rawCerts:       [][]byte{leaf65.Raw},
			verifiedChains: nil,
			expectErr:      false,
		},
		{
			name:           "Reject RSA Leaf In Chain",
			rawCerts:       [][]byte{leafRSA.Raw},
			verifiedChains: [][]*x509.Certificate{{leafRSA, caRSACert}},
			expectErr:      true,
		},
		{
			name:           "Reject Raw RSA Leaf",
			rawCerts:       [][]byte{leafRSA.Raw},
			verifiedChains: nil,
			expectErr:      true,
		},
		{
			name:           "Reject MLDSA Leaf Signed By RSA CA",
			rawCerts:       [][]byte{leafMLDSAbyRSA.Raw},
			verifiedChains: [][]*x509.Certificate{{leafMLDSAbyRSA, caRSACert}},
			expectErr:      true,
		},
		{
			name:           "Reject Empty Peer Certificates",
			rawCerts:       nil,
			verifiedChains: nil,
			expectErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyMLDSAPeerCertificate(tc.rawCerts, tc.verifiedChains)
			if tc.expectErr && err == nil {
				t.Errorf("Expected error but got nil")
			} else if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestMLDSATLSHandshake(t *testing.T) {
	// ML-DSA CA
	_, caCert, caPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "Root CA", true, nil, nil)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// ML-DSA Server & Client
	serverMLDSACert, _, _ := generateTestMLDSACert(t, mldsa.MLDSA65(), "localhost", false, caCert, caPriv)
	clientMLDSACert, _, _ := generateTestMLDSACert(t, mldsa.MLDSA65(), "client", false, caCert, caPriv)

	// RSA CA, Server & Client
	_, rsaCACert, rsaCAPriv := generateTestRSACert(t, "RSA Root CA", true, nil, nil)
	rsaPool := x509.NewCertPool()
	rsaPool.AddCert(rsaCACert)
	serverRSACert, _, _ := generateTestRSACert(t, "localhost", false, rsaCACert, rsaCAPriv)
	clientRSACert, _, _ := generateTestRSACert(t, "client", false, rsaCACert, rsaCAPriv)

	// Test 1: Successful Mutual ML-DSA Handshake
	t.Run("Successful Mutual MLDSA", func(t *testing.T) {
		cfg := &Config{EnableMLDSATLS: true}
		serverTLS := &tls.Config{
			Certificates: []tls.Certificate{serverMLDSACert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
		}
		cfg.applyMLDSAConfig(serverTLS)

		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientMLDSACert},
			RootCAs:      caPool,
			ServerName:   "localhost",
		}
		cfg.applyMLDSAConfig(clientTLS)

		cConn, sConn := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(2)
		var sErr, cErr error

		go func() {
			defer wg.Done()
			s := tls.Server(sConn, serverTLS)
			sErr = s.Handshake()
			s.Close()
		}()
		go func() {
			defer wg.Done()
			c := tls.Client(cConn, clientTLS)
			cErr = c.Handshake()
			c.Close()
		}()

		wg.Wait()
		if sErr != nil {
			t.Errorf("Server handshake failed: %v", sErr)
		}
		if cErr != nil {
			t.Errorf("Client handshake failed: %v", cErr)
		}
	})

	// Test 2: Server with ML-DSA rejects RSA Client
	t.Run("MLDSA Server Rejects RSA Client", func(t *testing.T) {
		cfg := &Config{EnableMLDSATLS: true}
		serverPool := x509.NewCertPool()
		serverPool.AddCert(caCert)
		serverPool.AddCert(rsaCACert)

		serverTLS := &tls.Config{
			Certificates: []tls.Certificate{serverMLDSACert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    serverPool,
		}
		cfg.applyMLDSAConfig(serverTLS)

		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientRSACert},
			RootCAs:      serverPool,
			ServerName:   "localhost",
		}

		cConn, sConn := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(2)
		var sErr, cErr error

		go func() {
			defer wg.Done()
			s := tls.Server(sConn, serverTLS)
			sErr = s.Handshake()
			s.Close()
		}()
		go func() {
			defer wg.Done()
			c := tls.Client(cConn, clientTLS)
			cErr = c.Handshake()
			c.Close()
		}()

		wg.Wait()
		if sErr == nil {
			t.Errorf("Expected server to reject RSA client certificate, but handshake succeeded (client err: %v)", cErr)
		}
	})

	// Test 3: Client with ML-DSA rejects RSA Server
	t.Run("MLDSA Client Rejects RSA Server", func(t *testing.T) {
		cfg := &Config{EnableMLDSATLS: true}
		clientPool := x509.NewCertPool()
		clientPool.AddCert(caCert)
		clientPool.AddCert(rsaCACert)

		serverTLS := &tls.Config{
			Certificates: []tls.Certificate{serverRSACert},
		}

		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientMLDSACert},
			RootCAs:      clientPool,
			ServerName:   "localhost",
		}
		cfg.applyMLDSAConfig(clientTLS)

		cConn, sConn := net.Pipe()
		var wg sync.WaitGroup
		wg.Add(2)
		var sErr, cErr error

		go func() {
			defer wg.Done()
			s := tls.Server(sConn, serverTLS)
			sErr = s.Handshake()
			s.Close()
		}()
		go func() {
			defer wg.Done()
			c := tls.Client(cConn, clientTLS)
			cErr = c.Handshake()
			c.Close()
		}()

		wg.Wait()
		if cErr == nil {
			t.Errorf("Expected client to reject RSA server certificate, but handshake succeeded (server err: %v)", sErr)
		}
	})
}

func TestLoadCredentialsMLDSA(t *testing.T) {
	dir := t.TempDir()

	// Write ML-DSA CA, server cert and key
	_, caCert, caPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "CA", true, nil, nil)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caCertPEM, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, serverCert, serverPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "server", false, caCert, caPriv)
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	serverPrivDER, err := x509.MarshalPKCS8PrivateKey(serverPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	serverPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivDER})
	serverCertPath := filepath.Join(dir, "server-cert.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(serverCertPath, serverCertPEM, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(serverKeyPath, serverPrivPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Write RSA server cert and key
	_, rsaCert, rsaPriv := generateTestRSACert(t, "rsa-server", false, nil, nil)
	rsaCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert.Raw})
	rsaPrivDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (RSA): %v", err)
	}
	rsaPrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPrivDER})
	rsaCertPath := filepath.Join(dir, "rsa-cert.pem")
	rsaKeyPath := filepath.Join(dir, "rsa-key.pem")
	if err := os.WriteFile(rsaCertPath, rsaCertPEM, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(rsaKeyPath, rsaPrivPEM, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfgMLDSA := &Config{EnableMLDSATLS: true}

	// Loading ML-DSA server and client credentials should succeed
	serverCreds, err := cfgMLDSA.LoadServerCredentials(caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Errorf("LoadServerCredentials failed for ML-DSA: %v", err)
	}
	if serverCreds == nil {
		t.Errorf("Expected serverCreds != nil")
	}

	clientCreds, err := cfgMLDSA.LoadClientCredentials(caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Errorf("LoadClientCredentials failed for ML-DSA: %v", err)
	}
	if clientCreds == nil {
		t.Errorf("Expected clientCreds != nil")
	}

	// Loading RSA credentials when EnableMLDSATLS is true should fail
	_, err = cfgMLDSA.LoadServerCredentials(caPath, rsaCertPath, rsaKeyPath)
	if err == nil {
		t.Errorf("Expected error loading RSA cert for ML-DSA server, got nil")
	}

	_, err = cfgMLDSA.LoadClientCredentials(caPath, rsaCertPath, rsaKeyPath)
	if err == nil {
		t.Errorf("Expected error loading RSA cert for ML-DSA client, got nil")
	}
}

