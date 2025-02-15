// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main is a gRPC server that buffers
// device-registration requests and streams them up to the device
// registry service.
//
// See "Provisioning Appliance Proxy/Buffer: Design Notes"[1] for
// details.
//
// [1] https://docs.google.com/document/d/1vQKMhrAVsqoC2sn4HJ5D7kj-wx3QovFWWRA3F3jTPSI
//     FIXME: Replace above with a pointer to markdown TBD.
//
// TODO: Stream requests up to the cloud RoT-Registry service.
//
// FIXME: Document idempotence/atomicity/durability/etc. details here
// (copied from design doc) once we settle on them (still unsettled at
// the time of this writing).

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
)

var (
	port   = flag.Int("port", 0, "the port to bind the server on; required")
	dbPath = flag.String("db_path", "", "the path to the database file")
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

	// TODO: Add secure connection via TLS credentials.
	server := grpc.NewServer()

	// Register server
	pbp.RegisterProxyBufferServiceServer(server, proxybuffer.NewProxyBufferServer(database))

	// Block and serve RPCs
	server.Serve(listener)
}
