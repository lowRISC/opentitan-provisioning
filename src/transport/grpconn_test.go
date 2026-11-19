// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package grpconn

import (
	"context"
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

	"google.golang.org/grpc/credentials"
)

func TestApplyMLKEMConfig(t *testing.T) {
	tlsConfig := &tls.Config{}
	applyMLKEMConfig(tlsConfig)

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion %v, got %v", tls.VersionTLS13, tlsConfig.MinVersion)
	}

	found := false
	for _, curve := range tlsConfig.CurvePreferences {
		if curve == tls.X25519MLKEM768 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected MLKEM curve to be present")
	}
}

func TestApplyMLDSAConfig(t *testing.T) {
	tlsConfig := &tls.Config{}
	applyMLDSAConfig(tlsConfig)

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion %v, got %v", tls.VersionTLS13, tlsConfig.MinVersion)
	}
	if tlsConfig.VerifyPeerCertificate == nil {
		t.Errorf("Expected VerifyPeerCertificate to be set")
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
			name:           "Reject Empty VerifiedChains",
			rawCerts:       [][]byte{leaf65.Raw},
			verifiedChains: nil,
			expectErr:      true,
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
		serverTLS := &tls.Config{
			Certificates: []tls.Certificate{serverMLDSACert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
		}
		applyMLKEMConfig(serverTLS)
		applyMLDSAConfig(serverTLS)

		clientTLS := &tls.Config{
			Certificates: []tls.Certificate{clientMLDSACert},
			RootCAs:      caPool,
			ServerName:   "localhost",
		}
		applyMLKEMConfig(clientTLS)
		applyMLDSAConfig(clientTLS)

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
		serverPool := x509.NewCertPool()
		serverPool.AddCert(caCert)
		serverPool.AddCert(rsaCACert)

		serverTLS := &tls.Config{
			Certificates: []tls.Certificate{serverMLDSACert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    serverPool,
		}
		applyMLDSAConfig(serverTLS)

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
		applyMLDSAConfig(clientTLS)

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

	// Loading ML-DSA server and client credentials should succeed
	serverCreds, err := LoadServerCredentials(caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Errorf("LoadServerCredentials failed for ML-DSA: %v", err)
	}
	if serverCreds == nil {
		t.Errorf("Expected serverCreds != nil")
	}

	clientCreds, err := LoadClientCredentials(caPath, serverCertPath, serverKeyPath)
	if err != nil {
		t.Errorf("LoadClientCredentials failed for ML-DSA: %v", err)
	}
	if clientCreds == nil {
		t.Errorf("Expected clientCreds != nil")
	}

	// Loading RSA credentials should fail
	_, err = LoadServerCredentials(caPath, rsaCertPath, rsaKeyPath)
	if err == nil {
		t.Errorf("Expected error loading RSA cert for server, got nil")
	}

	_, err = LoadClientCredentials(caPath, rsaCertPath, rsaKeyPath)
	if err == nil {
		t.Errorf("Expected error loading RSA cert for client, got nil")
	}
}

func writeCertAndKeyPEM(t *testing.T, dir, prefix string, cert *x509.Certificate, priv any) (string, string) {
	t.Helper()
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey(%s): %v", prefix, err)
	}
	certPath, keyPath := filepath.Join(dir, prefix+"-cert.pem"), filepath.Join(dir, prefix+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatalf("WriteFile(%s): %v", keyPath, err)
	}
	return certPath, keyPath
}

func runGRPCHandshake(t *testing.T, serverCreds, clientCreds credentials.TransportCredentials) (tls.ConnectionState, tls.ConnectionState, error, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	var srvState tls.ConnectionState
	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			srvErr = err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		var auth credentials.AuthInfo
		if _, auth, srvErr = serverCreds.ServerHandshake(c); srvErr == nil {
			srvState = auth.(credentials.TLSInfo).State
		}
	}()

	rawCli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer rawCli.Close()
	_ = rawCli.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, auth, cliErr := clientCreds.ClientHandshake(ctx, "localhost", rawCli)
	var cliState tls.ConnectionState
	if cliErr == nil {
		cliState = auth.(credentials.TLSInfo).State
	}
	wg.Wait()
	return srvState, cliState, srvErr, cliErr
}

func TestMixedMigrationHandshakes(t *testing.T) {
	dir := t.TempDir()
	_, mldsaCA, mldsaCAPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "MLDSA-CA", true, nil, nil)
	_, mldsaSrv, mldsaSrvPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "localhost", false, mldsaCA, mldsaCAPriv)
	_, mldsaCli, mldsaCliPriv := generateTestMLDSACert(t, mldsa.MLDSA65(), "localhost", false, mldsaCA, mldsaCAPriv)
	_, rsaCA, rsaCAPriv := generateTestRSACert(t, "RSA-CA", true, nil, nil)
	_, rsaSrv, rsaSrvPriv := generateTestRSACert(t, "localhost", false, rsaCA, rsaCAPriv)
	_, rsaCli, rsaCliPriv := generateTestRSACert(t, "localhost", false, rsaCA, rsaCAPriv)

	mldsaCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mldsaCA.Raw})
	rsaCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCA.Raw})
	mldsaCAPath, mixedCAPath := filepath.Join(dir, "ca-mldsa.pem"), filepath.Join(dir, "ca-mixed.pem")
	for p, data := range map[string][]byte{mldsaCAPath: mldsaCAPEM, mixedCAPath: append(append([]byte{}, mldsaCAPEM...), rsaCAPEM...)} {
		if err := os.WriteFile(p, data, 0644); err != nil {
			t.Fatalf("WriteFile(%s): %v", p, err)
		}
	}
	mldsaSrvCert, mldsaSrvKey := writeCertAndKeyPEM(t, dir, "srv-mldsa", mldsaSrv, mldsaSrvPriv)
	mldsaCliCert, mldsaCliKey := writeCertAndKeyPEM(t, dir, "cli-mldsa", mldsaCli, mldsaCliPriv)
	rsaSrvCert, rsaSrvKey := writeCertAndKeyPEM(t, dir, "srv-rsa", rsaSrv, rsaSrvPriv)
	rsaCliCert, rsaCliKey := writeCertAndKeyPEM(t, dir, "cli-rsa", rsaCli, rsaCliPriv)

	mustLoad := func(creds credentials.TransportCredentials, err error) credentials.TransportCredentials {
		if err != nil {
			t.Fatalf("load credentials: %v", err)
		}
		return creds
	}

	rsaPool := x509.NewCertPool()
	rsaPool.AddCert(rsaCA)
	rsaSrvTLS, err := tls.LoadX509KeyPair(rsaSrvCert, rsaSrvKey)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(rsaSrv): %v", err)
	}
	rsaCliTLS, err := tls.LoadX509KeyPair(rsaCliCert, rsaCliKey)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(rsaCli): %v", err)
	}
	legacySrv := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{rsaSrvTLS}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: rsaPool, MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519},
	})
	legacyCli := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{rsaCliTLS}, RootCAs: rsaPool,
		MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519},
	})

	mixedPool := x509.NewCertPool()
	mixedPool.AddCert(mldsaCA)
	mixedPool.AddCert(rsaCA)
	mldsaCliTLS, err := tls.LoadX509KeyPair(mldsaCliCert, mldsaCliKey)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(mldsaCli): %v", err)
	}
	tls13RSACli := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{rsaCliTLS}, RootCAs: mixedPool,
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})
	tls13NoMLKEMCli := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{mldsaCliTLS}, RootCAs: mixedPool,
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
	})

	// Mixed mode is enabled by providing fallback cert/key alongside a mixed CA bundle;
	// leaving fallback empty enforces strict PQ-only (ML-KEM + ML-DSA + TLS 1.3).
	mixedSrv := mustLoad((&Config{FallbackCertFilename: rsaSrvCert, FallbackKeyFilename: rsaSrvKey}).LoadServerCredentials(mixedCAPath, mldsaSrvCert, mldsaSrvKey))
	mixedSrvRev := mustLoad((&Config{FallbackCertFilename: mldsaSrvCert, FallbackKeyFilename: mldsaSrvKey}).LoadServerCredentials(mixedCAPath, rsaSrvCert, rsaSrvKey))
	mixedCli := mustLoad((&Config{FallbackCertFilename: rsaCliCert, FallbackKeyFilename: rsaCliKey}).LoadClientCredentials(mixedCAPath, mldsaCliCert, mldsaCliKey))
	enfSrv := mustLoad(LoadServerCredentials(mixedCAPath, mldsaSrvCert, mldsaSrvKey))
	enfCli := mustLoad(LoadClientCredentials(mldsaCAPath, mldsaCliCert, mldsaCliKey))

	for _, tc := range []struct {
		name     string
		srv, cli credentials.TransportCredentials
		wantErr  bool
		wantPQC  bool
	}{
		{"Mixed_to_Mixed_PQC", mixedSrv, mixedCli, false, true},
		{"Mixed_reversed_cert_order_PQC", mixedSrvRev, mixedCli, false, true},
		{"Mixed_srv_to_Enforce_cli_PQC", mixedSrv, enfCli, false, true},
		{"Enforce_srv_to_Mixed_cli_PQC", enfSrv, mixedCli, false, true},
		{"Mixed_srv_accepts_Legacy_cli", mixedSrv, legacyCli, false, false},
		{"Mixed_cli_connects_Legacy_srv", legacySrv, mixedCli, false, false},
		{"Enforce_srv_rejects_Legacy_cli", enfSrv, legacyCli, true, false},
		{"Enforce_srv_rejects_TLS13_RSA_cli_with_mixed_CA", enfSrv, tls13RSACli, true, false},
		{"Enforce_srv_rejects_TLS13_non_MLKEM_cli", enfSrv, tls13NoMLKEMCli, true, false},
		{"Enforce_cli_rejects_Legacy_srv", legacySrv, enfCli, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srvState, cliState, srvErr, cliErr := runGRPCHandshake(t, tc.srv, tc.cli)
			if tc.wantErr {
				if srvErr == nil && cliErr == nil {
					t.Fatalf("expected handshake failure")
				}
				return
			}
			if srvErr != nil || cliErr != nil {
				t.Fatalf("handshake failed: server=%v client=%v", srvErr, cliErr)
			}
			if tc.wantPQC {
				if srvState.CurveID != tls.X25519MLKEM768 || cliState.CurveID != tls.X25519MLKEM768 {
					t.Errorf("expected X25519MLKEM768, got srv=%v cli=%v", srvState.CurveID, cliState.CurveID)
				}
				if err := verifyMLDSAPeerCertificate(nil, srvState.VerifiedChains); err != nil {
					t.Errorf("expected ML-DSA client cert: %v", err)
				}
				if err := verifyMLDSAPeerCertificate(nil, cliState.VerifiedChains); err != nil {
					t.Errorf("expected ML-DSA server cert: %v", err)
				}
			} else if len(srvState.PeerCertificates) == 0 || len(cliState.PeerCertificates) == 0 ||
				srvState.PeerCertificates[0].PublicKeyAlgorithm != x509.RSA || cliState.PeerCertificates[0].PublicKeyAlgorithm != x509.RSA {
				t.Errorf("expected RSA fallback certs, got srvPeers=%d cliPeers=%d", len(srvState.PeerCertificates), len(cliState.PeerCertificates))
			}
		})
	}

	if _, err := (&Config{FallbackCertFilename: rsaSrvCert}).LoadServerCredentials(mixedCAPath, mldsaSrvCert, mldsaSrvKey); err == nil {
		t.Errorf("expected error when only FallbackCertFilename is specified")
	}
	if _, err := (&Config{FallbackKeyFilename: rsaSrvKey}).LoadServerCredentials(mixedCAPath, mldsaSrvCert, mldsaSrvKey); err == nil {
		t.Errorf("expected error when only FallbackKeyFilename is specified")
	}

	// Primary and fallback certs issued by CAs with identical Subject DNs must be rejected.
	_, sameDNRSACA, sameDNRSACAPriv := generateTestRSACert(t, "MLDSA-CA", true, nil, nil)
	_, sameDNRSASrv, sameDNRSASrvPriv := generateTestRSACert(t, "localhost", false, sameDNRSACA, sameDNRSACAPriv)
	sameDNRSACert, sameDNRSAKey := writeCertAndKeyPEM(t, dir, "srv-rsa-samedn", sameDNRSASrv, sameDNRSASrvPriv)
	if _, err := (&Config{FallbackCertFilename: sameDNRSACert, FallbackKeyFilename: sameDNRSAKey}).LoadServerCredentials(mixedCAPath, mldsaSrvCert, mldsaSrvKey); err == nil {
		t.Errorf("expected error when primary and fallback certs share the same issuer DN")
	}

	// Mixed mode requires at least one ML-DSA certificate (reject RSA + RSA).
	_, otherRSACA, otherRSACAPriv := generateTestRSACert(t, "RSA-CA-2", true, nil, nil)
	_, otherRSASrv, otherRSASrvPriv := generateTestRSACert(t, "localhost", false, otherRSACA, otherRSACAPriv)
	otherRSACert, otherRSAKey := writeCertAndKeyPEM(t, dir, "srv-rsa-other", otherRSASrv, otherRSASrvPriv)
	if _, err := (&Config{FallbackCertFilename: otherRSACert, FallbackKeyFilename: otherRSAKey}).LoadServerCredentials(mixedCAPath, rsaSrvCert, rsaSrvKey); err == nil {
		t.Errorf("expected error when neither primary nor fallback cert uses ML-DSA")
	}
}
