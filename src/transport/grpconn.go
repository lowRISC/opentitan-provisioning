// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package grpconn implements the gRPC connection utility functions
package grpconn

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

type Config struct {
	EnableMLKEMTLS bool
	EnableMLDSATLS bool
}

func (c *Config) applyMLKEMConfig(tlsConfig *tls.Config) {
	if c.EnableMLKEMTLS {
		// Strictly prefer MLKEM. This enforces that clients must support MLKEM key exchange.
		tlsConfig.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768,
		}
		tlsConfig.MinVersion = tls.VersionTLS13
	}
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

// verifyMLDSAPeerCertificate verifies that the peer's certificate and every
// certificate in its verified chain (leaf, intermediates, and root CA) use
// ML-DSA public keys and signature algorithms. Standard TLS handles cryptographic
// signature and root CA trust verification; this function enforces post-quantum
// algorithm policy across the entire chain.
func verifyMLDSAPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		var lastErr error
		for _, chain := range verifiedChains {
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

	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificates provided")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}
	if !isMLDSAPublicKeyAlgo(cert.PublicKeyAlgorithm) {
		return fmt.Errorf("peer certificate public key algorithm %v is not MLDSA", cert.PublicKeyAlgorithm)
	}
	if !isMLDSASignatureAlgo(cert.SignatureAlgorithm) {
		return fmt.Errorf("peer certificate signature algorithm %v is not MLDSA", cert.SignatureAlgorithm)
	}
	return nil
}

func (c *Config) applyMLDSAConfig(tlsConfig *tls.Config) {
	if c.EnableMLDSATLS {
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
}

// LoadServerCredentials returns server side mTLS transport credentials.
// `rootsFilename` should point to the client CA root certificates in PEM
// format.
func (c *Config) LoadServerCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	if c.EnableMLDSATLS && !isMLDSAPrivateKey(cert.PrivateKey) {
		return nil, fmt.Errorf("server certificate key is not an MLDSA private key (got %T)", cert.PrivateKey)
	}

	var tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          certPool,
		InsecureSkipVerify: false,
	}

	c.applyMLKEMConfig(tlsConfig)
	c.applyMLDSAConfig(tlsConfig)

	return credentials.NewTLS(tlsConfig), nil
}

// LoadClientCredentials returns client side mTLS transport credentials.
// `rootsFilename` should point to the server CA root certificates in PEM
// format.
func (c *Config) LoadClientCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	if c.EnableMLDSATLS && !isMLDSAPrivateKey(cert.PrivateKey) {
		return nil, fmt.Errorf("client certificate key is not an MLDSA private key (got %T)", cert.PrivateKey)
	}

	var tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}

	c.applyMLKEMConfig(tlsConfig)
	c.applyMLDSAConfig(tlsConfig)

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