// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package grpconn implements the gRPC connection utility functions
package grpconn

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/lowRISC/opentitan-provisioning/src/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// loadCertPool returns a certificate pool initialized with the CA certificates
// included in the `rootFilename` PEM file path.
func loadCertPool(rootsFilename string) (*x509.CertPool, error) {
	roots, err := utils.ReadFile(rootsFilename)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(roots) {
		return nil, fmt.Errorf("failed to add root CA certificates: %v", err)
	}
	return certPool, nil
}

// Config configures optional classical fallback certificates for mixed
// PQ/classical TLS migration. When empty (the default), ML-KEM and ML-DSA
// are strictly enforced.
type Config struct {
	FallbackCertFilename string
	FallbackKeyFilename  string
}

func (c *Config) isMixed() bool {
	return c != nil && (c.FallbackCertFilename != "" || c.FallbackKeyFilename != "")
}

func applyMLKEMConfig(tlsConfig *tls.Config) {
	// Strictly prefer MLKEM. This enforces that clients must support MLKEM key exchange.
	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519MLKEM768,
	}
	tlsConfig.MinVersion = tls.VersionTLS13
}

func isMLDSAPublicKeyAlgo(algo x509.PublicKeyAlgorithm) bool {
	return algo == x509.MLDSA
}

func isMLDSASignatureAlgo(algo x509.SignatureAlgorithm) bool {
	return algo == x509.MLDSA44 || algo == x509.MLDSA65 || algo == x509.MLDSA87
}

func isMLDSAPrivateKey(priv crypto.PrivateKey) bool {
	if _, ok := priv.(*mldsa.PrivateKey); ok {
		return true
	}
	if signer, ok := priv.(crypto.Signer); ok {
		if _, ok := signer.Public().(*mldsa.PublicKey); ok {
			return true
		}
	}
	return false
}

// verifyMLDSAPeerCertificate verifies that every certificate in the peer's
// verified chain (leaf, intermediates, and root CA) uses ML-DSA public keys
// and signature algorithms. Standard TLS handles cryptographic signature and
// root CA trust verification; this function enforces post-quantum algorithm
// policy across the entire chain.
func verifyMLDSAPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return fmt.Errorf("no verified certificate chains provided")
	}

	var lastErr error
	for _, chain := range verifiedChains {
		if len(chain) == 0 {
			lastErr = fmt.Errorf("empty certificate chain provided")
			continue
		}
		chainOK := true
		for i, cert := range chain {
			if !isMLDSAPublicKeyAlgo(cert.PublicKeyAlgorithm) {
				lastErr = fmt.Errorf("certificate at index %d in chain has non-MLDSA public key algorithm %v", i, cert.PublicKeyAlgorithm)
				chainOK = false
				break
			}
			if !isMLDSASignatureAlgo(cert.SignatureAlgorithm) {
				lastErr = fmt.Errorf("certificate at index %d in chain has non-MLDSA signature algorithm %v", i, cert.SignatureAlgorithm)
				chainOK = false
				break
			}
		}
		if chainOK {
			return nil
		}
	}
	return lastErr
}

func applyMLDSAConfig(tlsConfig *tls.Config) {
	// ML-DSA requires TLS 1.3.
	tlsConfig.MinVersion = tls.VersionTLS13

	for i := range tlsConfig.Certificates {
		if isMLDSAPrivateKey(tlsConfig.Certificates[i].PrivateKey) {
			tlsConfig.Certificates[i].SupportedSignatureAlgorithms = []tls.SignatureScheme{
				tls.MLDSA44,
				tls.MLDSA65,
				tls.MLDSA87,
			}
		}
	}

	// Chain ML-DSA certificate verification onto any existing VerifyPeerCertificate
	// hook. Standard TLS verification against RootCAs/ClientCAs runs before this hook;
	// here we strictly enforce that the peer certificate and all certificates in its
	// verified chain (intermediates and root) use ML-DSA keys and signatures.
	prevVerifyPeerCertificate := tlsConfig.VerifyPeerCertificate
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if prevVerifyPeerCertificate != nil {
			if err := prevVerifyPeerCertificate(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		return verifyMLDSAPeerCertificate(rawCerts, verifiedChains)
	}
}

func applyFallbackLogging(role string, tlsConfig *tls.Config) {
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		peer := cs.ServerName
		if len(cs.PeerCertificates) > 0 && cs.PeerCertificates[0].Subject.CommonName != "" {
			peer = cs.PeerCertificates[0].Subject.CommonName
		}
		if cs.CurveID != tls.X25519MLKEM768 {
			if cs.Version < tls.VersionTLS13 && cs.CurveID == 0 {
				log.Printf("WARNING: TLS mixed mode (%s, peer=%q): non-X25519MLKEM768 key exchange (TLS 0x%x)", role, peer, cs.Version)
			} else {
				log.Printf("WARNING: TLS mixed mode (%s, peer=%q): non-X25519MLKEM768 curve %v (TLS 0x%x)", role, peer, cs.CurveID, cs.Version)
			}
		}
		if err := verifyMLDSAPeerCertificate(nil, cs.VerifiedChains); err != nil {
			log.Printf("WARNING: TLS mixed mode (%s, peer=%q): non-MLDSA peer cert (%v)", role, peer, err)
		}
		return nil
	}
}

func (c *Config) loadCertificates(role, certFilename, keyFilename string) ([]tls.Certificate, error) {
	primary, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	if !c.isMixed() {
		if !isMLDSAPrivateKey(primary.PrivateKey) {
			return nil, fmt.Errorf("%s certificate key is not an MLDSA private key (got %T)", role, primary.PrivateKey)
		}
		return []tls.Certificate{primary}, nil
	}

	if c.FallbackCertFilename == "" || c.FallbackKeyFilename == "" {
		return nil, fmt.Errorf("both fallback certificate and fallback key must be specified")
	}
	fallback, err := tls.LoadX509KeyPair(c.FallbackCertFilename, c.FallbackKeyFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to load fallback %s certificate/key: %w", role, err)
	}
	if primary.Leaf != nil && fallback.Leaf != nil && bytes.Equal(primary.Leaf.RawIssuer, fallback.Leaf.RawIssuer) {
		return nil, fmt.Errorf("primary and fallback %s certificates share the same issuer DN (%q); mixed TLS requires distinct CA Subject DNs", role, primary.Leaf.Issuer.String())
	}
	certs := []tls.Certificate{primary, fallback}
	// List ML-DSA first so Go's crypto/tls prefers it whenever the peer supports it.
	if isMLDSAPrivateKey(certs[1].PrivateKey) && !isMLDSAPrivateKey(certs[0].PrivateKey) {
		certs[0], certs[1] = certs[1], certs[0]
	}
	if !isMLDSAPrivateKey(certs[0].PrivateKey) {
		return nil, fmt.Errorf("mixed TLS requires an MLDSA %s certificate (got %T and %T)", role, primary.PrivateKey, fallback.PrivateKey)
	}
	return certs, nil
}

// LoadServerCredentials returns server side mTLS transport credentials with
// strict ML-KEM and ML-DSA enforcement.
func LoadServerCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	return (&Config{}).LoadServerCredentials(rootsFilename, certFilename, keyFilename)
}

// LoadServerCredentials returns server side mTLS transport credentials.
// `rootsFilename` should point to the client CA root certificates in PEM
// format.
func (c *Config) LoadServerCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	certs, err := c.loadCertificates("server", certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	var tlsConfig = &tls.Config{
		Certificates:       certs,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          certPool,
		InsecureSkipVerify: false,
	}

	if c.isMixed() {
		applyFallbackLogging("server", tlsConfig)
	} else {
		applyMLKEMConfig(tlsConfig)
		applyMLDSAConfig(tlsConfig)
	}

	return credentials.NewTLS(tlsConfig), nil
}

// LoadClientCredentials returns client side mTLS transport credentials with
// strict ML-KEM and ML-DSA enforcement.
func LoadClientCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	return (&Config{}).LoadClientCredentials(rootsFilename, certFilename, keyFilename)
}

// LoadClientCredentials returns client side mTLS transport credentials.
// `rootsFilename` should point to the server CA root certificates in PEM
// format.
func (c *Config) LoadClientCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	certs, err := c.loadCertificates("client", certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	var tlsConfig = &tls.Config{
		Certificates: certs,
		RootCAs:      certPool,
	}

	if c.isMixed() {
		applyFallbackLogging("client", tlsConfig)
	} else {
		applyMLKEMConfig(tlsConfig)
		applyMLDSAConfig(tlsConfig)
	}

	return credentials.NewTLS(tlsConfig), nil
}

func ExtractClientIP(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("peer not found in context")
	}
	// Get the client's IP & DNS from the context
	clientIP, _, err := net.SplitHostPort(p.Addr.String())
	return clientIP, err
}

// CheckEndpointInterceptor is a gRPC unary interceptor that checks the client's IP address against
// the IP addresses and DNS in the client's certificate. If a match is found, the request is passed on
// to the next handler, otherwise an error is returned.
func CheckEndpointInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("peer not found in context")
	}
	// Get the client's IP & DNS from the context
	clientIP, _ := ExtractClientIP(ctx)

	// Get the client's certificate from the context
	clientCert := p.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0]
	// Extract the IP and DNS from the certificate
	match := false
	for _, ip := range clientCert.IPAddresses {
		if clientIP == ip.String() {
			match = true
			break
		}
	}

	hostname := "no host"
	if !match {
		skipDNS := false
		ips, err := net.LookupAddr(clientIP)
		if err != nil {
			skipDNS = true
		}
		if !skipDNS {
			clientDNS := ips[0]
			dnsParts := strings.Split(clientDNS, ".")
			hostname = dnsParts[0]
			hostname = strings.ToLower(hostname)

			for _, dns := range clientCert.DNSNames {
				dns = strings.ToLower(dns)
				if hostname == dns {
					match = true
					break
				}
			}
		}
	}

	// Compare the client's IP or DNS name with the IP or DNS names in the certificate
	if !match {
		return nil, fmt.Errorf("client IP %q or DNS name %s does not match the IP or DNS name in the certificate", clientIP, hostname)
	}
	// If the IP or DNS name match, proceed with the next handler
	return handler(ctx, req)
}
