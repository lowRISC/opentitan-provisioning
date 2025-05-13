// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main is a gRPC server that buffers
// device-registration requests and streams them up to the device
// registry service.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/httpregistry"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/filedb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/syncer"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
)

var (
	// Database
	port   = flag.Int("port", 0, "the port to bind the server on; required")
	dbPath = flag.String("db_path", "", "the path to the database file")
	// Registry client
	registerDeviceURL      = flag.String("register_device_url", "", "URL to call for RegisterDevice")
	batchRegisterDeviceURL = flag.String("batch_register_device_url", "", "URL to call for BatchRegisterDevice")
	registryHeadersFile    = flag.String("registry_headers_file", "", "File containing all the headers. Each line should contain a header in the format `NAME: VALUE`.")
	// Syncer
	enableSyncer       = flag.Bool("enable_syncer", false, "If true, will create an HTTP register and a syncer.")
	syncerFrequency     = flag.String("syncer_frequency", "10m", "Frequency with which the syncer runs. Must use a valid Go duration string (see https://pkg.go.dev/time#ParseDuration). Defaults to 10 minutes.")
	syncerRecordsPerRun = flag.Int("syncer_records_per_run", 100, "Number of records for the syncer to process per run. Defaults to 100.")
	// gRPC server
	enableTLS   = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	serviceKey  = flag.String("service_key", "", "File path to the PEM encoding of the server's private key")
	serviceCert = flag.String("service_cert", "", "File path to the PEM encoding of the server's certificate chain")
	caRootCerts = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
)

func parseHeadersFile(filepath string) (map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open headers file %s: %v", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	headers := make(map[string]string)
	lineCount := 0
	for scanner.Scan() {
		lineCount += 1
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("failed to parse header in file, line %d", lineCount)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		headers[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading headers file: %v", err)
	}
	return headers, nil
}

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

	if *enableSyncer {
		// Initialize the registry client
		registryHeaders, err := parseHeadersFile(*registryHeadersFile)
		if err != nil {
			log.Fatalf("Failed to parse registry headers: %v", err)
		}
		registry, err := httpregistry.New(&httpregistry.RegistryConfig{
			RegisterDeviceURL:      *registerDeviceURL,
			BatchRegisterDeviceURL: *batchRegisterDeviceURL,
			Headers:                map[string]string(registryHeaders),
		})
		if err != nil {
			log.Fatalf("Failed to initialize registry client: %v", err)
		}

		// Initialize syncer job
		syncerOpts := &syncer.Options{
			Frequency:     *syncerFrequency,
			RecordsPerRun: *syncerRecordsPerRun,
		}
		syncerJob, err := syncer.New(database, registry, syncerOpts)
		if err != nil {
			log.Fatalf("Failed to initialize syncer job: %v", err)
		}
		syncerJob.Start()
	}

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
