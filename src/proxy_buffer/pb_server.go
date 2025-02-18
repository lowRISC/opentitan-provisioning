// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main is a gRPC server that buffers
// device-registration requests and streams them up to the device
// registry service.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/filedb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
)

var (
	port        = flag.Int("port", 0, "the port to bind the server on; required")
	dbPath      = flag.String("db_path", "", "the path to the database file")
	enableTLS   = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	serviceKey  = flag.String("service_key", "", "File path to the PEM encoding of the server's private key")
	serviceCert = flag.String("service_cert", "", "File path to the PEM encoding of the server's certificate chain")
	caRootCerts = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
)

func main() {
	flag.Parse()
	if *port == 0 {
		log.Fatalf("`port` parameter missing")
	}

	// Initialize the datastore layer.
	conn, err := filedb.New(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	database := db.New(conn)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Server failed to listen: %v", err)
	}
	log.Printf("Server is now listening on port: %d", *port)

	opts := []grpc.ServerOption{}
	if *enableTLS {
		credentials, err := grpconn.LoadServerCredentials(*caRootCerts, *serviceCert, *serviceKey)
		if err != nil {
			log.Fatalf("Failed to load server credentials: %v", err)
		}
		opts = append(opts, grpc.Creds(credentials))
		opts = append(opts, grpc.UnaryInterceptor(grpconn.CheckEndpointInterceptor))
	}
	server := grpc.NewServer(opts...)

	// Register server
	pbp.RegisterProxyBufferServiceServer(server, proxybuffer.NewProxyBufferServer(database))

	// Block and serve RPCs
	server.Serve(listener)
}
