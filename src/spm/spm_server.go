// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implements a Secure Provisioning Module server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/spm"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

var (
	port         = flag.Int("port", 0, "The port to bind the server on; required")
	hsmPWFile    = flag.String("hsm_pw", "", "File path to the HSM's Password; required for TPM")
	hsmSOPath    = flag.String("hsm_so", "", "File path to the PCKS#11 .so library used to interface to the HSM")
	enableTLS    = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	serviceKey   = flag.String("service_key", "", "File path to the PEM encoding of the server's private key")
	serviceCert  = flag.String("service_cert", "", "File path to the PEM encoding of the server's certificate chain")
	caRootCerts  = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
	spmConfigDir = flag.String("spm_config_dir", "", "Path to the configuration directory.")
	version      = flag.Bool("version", false, "Print version information and exit")
)

func startSPMServer() (*grpc.Server, error) {
	opts := []grpc.ServerOption{}
	if *enableTLS {
		credentials, err := grpconn.LoadServerCredentials(*caRootCerts, *serviceCert, *serviceKey)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(credentials))
		opts = append(opts, grpc.UnaryInterceptor(grpconn.CheckEndpointInterceptor))
	}

	spmServer, err := spm.NewSpmServer(spm.Options{
		HSMSOLibPath: *hsmSOPath,
		SPMConfigDir: *spmConfigDir,
		HsmPWFile:    *hsmPWFile,
	})
	if err != nil {
		return nil, err
	}

	// Create a new gRPC server.
	server := grpc.NewServer(opts...)
	// Register the RegisterSpmServiceServer with the gRPC server.
	pbs.RegisterSpmServiceServer(server, spmServer)
	return server, nil
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

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Server failed to listen: %v", err)
	}

	// Start the SPM gRPC server.
	server, err := startSPMServer()
	if err != nil {
		log.Fatalf("failed to start SPM server: %v", err)
	}
	log.Printf("SPM server is now listening on port: %d", *port)

	// Block and serve incoming RPCs on the listener.
	if err := server.Serve(listener); err != nil {
		log.Fatalf("SPM server failed to start: %v", err)
	}
}
