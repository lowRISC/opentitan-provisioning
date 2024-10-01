// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implementes the Provisioning Appliance server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/pa/services/pa"
	pbr "github.com/lowRISC/opentitan-provisioning/src/registry_buffer/proto/registry_buffer_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

var (
	port          = flag.Int("port", 0, "the port to bind the server on; required")
	spmAddress    = flag.String("spm_address", "", "the SPM server address to connect to; required")
	enableRegBuff = flag.Bool("enable_rb", false, "Enable connectivity to the RegistryBuffer server; optional")
	rbAddress     = flag.String("rb_address", "", "the RegistryBuffer server address to connect to; required")
	enableTLS     = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	serviceKey    = flag.String("service_key", "", "File path to the PEM encoding of the server's private key")
	serviceCert   = flag.String("service_cert", "", "File path to the PEM encoding of the server's certificate chain")
	caRootCerts   = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
	version       = flag.Bool("version", false, "Print version information and exit")
)

func startPAServer(spmClient pbs.SpmServiceClient, rbClient pbr.RegistryBufferServiceClient) (*grpc.Server, error) {
	opts := []grpc.ServerOption{}
	auth_service.NewAuthControllerInstance(*enableTLS)
	if *enableTLS {
		credentials, err := grpconn.LoadServerCredentials(*caRootCerts, *serviceCert, *serviceKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(credentials))
	}
	interceptor := auth_service.NewAuthInterceptor(*enableTLS)
	opts = append(opts, grpc.UnaryInterceptor(interceptor.Unary))
	server := grpc.NewServer(opts...)
	pbp.RegisterProvisioningApplianceServiceServer(server, pa.NewProvisioningApplianceServer(spmClient, rbClient, *enableRegBuff))
	return server, nil
}

// startSPMClient starts the SPM gRPC client.
func startSPMClient() (pbs.SpmServiceClient, error) {
	opts := grpc.WithInsecure()
	if *enableTLS {
		credentials, err := grpconn.LoadClientCredentials(*caRootCerts, *serviceCert, *serviceKey)
		if err != nil {
			return nil, err
		}
		opts = grpc.WithTransportCredentials(credentials)
	}

	conn, err := grpc.Dial(*spmAddress, opts, grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	return pbs.NewSpmServiceClient(conn), nil
}

// startRegisterBufferClient starts the RegisterBuffer gRPC client.
func startRegisterBufferClient() (pbr.RegistryBufferServiceClient, error) {
	opts := grpc.WithInsecure()
	if *enableTLS {
		credentials, err := grpconn.LoadClientCredentials(*caRootCerts, *serviceCert, *serviceKey)
		if err != nil {
			return nil, err
		}
		opts = grpc.WithTransportCredentials(credentials)
	}

	conn, err := grpc.Dial(*rbAddress, opts, grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	return pbr.NewRegistryBufferServiceClient(conn), nil
}

func main() {
	// Parse command-line flags.
	flag.Parse()
	// If the version flag true then print the version and exit,
	// otherwise only print the vertion to the to log
	utils.PrintVersion(*version)

	if *port == 0 {
		log.Fatalf("`port` parameter missing")
	}

	// Create a network listener on the specified port.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("server failed to listen: %v", err)
	}

	if *spmAddress == "" {
		log.Fatalf("`spm_address` parameter missing")
	}

	log.Printf("starting SPM client at address: %q", *spmAddress)
	spmClient, err := startSPMClient()
	if err != nil {
		log.Fatalf("failed to initialize SPM client: %v", err)
	}

	var rbClient pbr.RegistryBufferServiceClient
	if *enableRegBuff {
		if *rbAddress == "" {
			log.Fatalf("`rb_address` parameter missing")
		}
		log.Printf("starting RegisterBuffer client at address: %q", *rbAddress)
		rbClient, err = startRegisterBufferClient()
		if err != nil {
			log.Fatalf("failed to initialize RegisterBuffer client: %v", err)
		}
	} else {
		log.Printf("Register Buffer module in not enabeld")
	}

	// Start the PA gRPC server.
	server, err := startPAServer(spmClient, rbClient)
	if err != nil {
		log.Fatalf("failed to start PA server: %v", err)
	}
	log.Printf("PA server is now listening on port: %d", *port)

	// Block and serve incoming RPCs on the listener.
	if err := server.Serve(listener); err != nil {
		log.Fatalf("PA server fatal error: %v", err)
	}
}
