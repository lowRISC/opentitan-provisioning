// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package grpconn implements the gRPC connection utility functions
package grpconn

import (
	"context"
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

// LoadServerCredentials returns server side mTLS transport credentials.
// `rootsFilename` should point to the client CA root certificates in PEM
// format.
func LoadServerCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          certPool,
		InsecureSkipVerify: false,
	}), nil
}

// LoadClientCredentials returns client side mTLS transport credentials.
// `rootsFilename` should point to the server CA root certificates in PEM
// format.
func LoadClientCredentials(rootsFilename, certFilename, keyFilename string) (credentials.TransportCredentials, error) {
	certPool, err := loadCertPool(rootsFilename)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}), nil
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
