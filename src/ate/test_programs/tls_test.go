// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implements a TLS connection test against the Provisioning Appliance.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"github.com/lowRISC/opentitan-provisioning/src/version/buildver"
)

var (
	paTarget            = flag.String("pa_target", "", "Endpoint address in gRPC name-syntax format, including port number.")
	loadBalancingPolicy = flag.String("load_balancing_policy", "", "gRPC load balancing policy. If not set, it will be selected by the gRPC library. For example: \"round_robin\" or \"pick_first\".")
	sku                 = flag.String("sku", "", "SKU string to initialize the PA session.")
	skuAuthPW           = flag.String("sku_auth_pw", "", "SKU authorization password string to initialize the PA session.")
	enableMTLS          = flag.Bool("enable_mtls", false, "Enable mTLS secure channel.")
	clientKey           = flag.String("client_key", "", "File path to the PEM encoding of the client's private key.")
	clientCert          = flag.String("client_cert", "", "File path to the PEM encoding of the client's certificate chain.")
	caRootCerts         = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates.")
	enableMLKEMTLS      = flag.Bool("enable_mlkem_tls", false, "Enable MLKEM TLS configuration; optional")
	enableMLDSATLS      = flag.Bool("enable_mldsa_tls", false, "Enable MLDSA certificate verification TLS configuration; optional")
)

type customResolverBuilder struct {
	scheme string
}

func (b *customResolverBuilder) Scheme() string {
	return b.scheme
}

func (b *customResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	endpoint := target.Endpoint()
	if endpoint == "" {
		endpoint = target.URL.Path
	}
	endpoint = strings.TrimPrefix(endpoint, "/")
	parts := strings.Split(endpoint, ",")
	var addrs []resolver.Address
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			addrs = append(addrs, resolver.Address{Addr: part})
		}
	}
	if err := cc.UpdateState(resolver.State{Addresses: addrs}); err != nil {
		return nil, err
	}
	return &nopResolver{}, nil
}

type nopResolver struct{}

func (*nopResolver) ResolveNow(resolver.ResolveNowOptions) {}
func (*nopResolver) Close()                                {}

func init() {
	resolver.Register(&customResolverBuilder{scheme: "ipv4"})
	resolver.Register(&customResolverBuilder{scheme: "ipv6"})
}

func main() {
	flag.Parse()

	log.Println(buildver.FormattedStr())

	if *paTarget == "" {
		log.Fatal("--pa_target not set. This is a required argument.")
	}

	if *enableMTLS {
		if *clientKey == "" || *clientCert == "" || *caRootCerts == "" {
			log.Fatal("--client_key, --client_cert, and --ca_root_certs are required arguments when --enable_mtls is set.")
		}
	}

	var opts []grpc.DialOption
	if *enableMTLS {
		creds, err := (&grpconn.Config{
			EnableMLKEMTLS: *enableMLKEMTLS,
			EnableMLDSATLS: *enableMLDSATLS,
		}).LoadClientCredentials(*caRootCerts, *clientCert, *clientKey)
		if err != nil {
			log.Fatalf("Failed to load client credentials: %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if *loadBalancingPolicy != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(fmt.Sprintf(`{"loadBalancingConfig": [{"%s": {}}]}`, *loadBalancingPolicy)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *paTarget, append(opts, grpc.WithBlock())...)
	if err != nil {
		log.Fatalf("Failed to dial PA at %q: %v", *paTarget, err)
	}
	defer conn.Close()

	client := pbp.NewProvisioningApplianceServiceClient(conn)

	initReq := &pbp.InitSessionRequest{
		Sku:     *sku,
		SkuAuth: *skuAuthPW,
	}
	initResp, err := client.InitSession(ctx, initReq)
	if err != nil {
		log.Fatalf("InitSession with PA failed: %v", err)
	}
	if initResp.SkuSessionToken == "" {
		log.Fatal("InitSession returned empty SKU session token.")
	}

	log.Println("TLS Connection to PA established successfully.")

	if _, err := client.CloseSession(ctx, &pbp.CloseSessionRequest{}); err != nil {
		log.Fatalf("CloseSession with PA failed: %v", err)
	}
}
