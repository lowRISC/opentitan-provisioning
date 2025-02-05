// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implementes Provisioning Appliance load test
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
)

const (
	// Maximum number of buffered calls. This limits the number of concurrent
	// calls to ensure the program does not run out of memory.
	maxBufferedCallResults = 100000
)

var (
	paAddress           = flag.String("pa_address", "", "the PA server address to connect to; required")
	enableTLS           = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	clientKey           = flag.String("client_key", "", "File path to the PEM encoding of the client's private key")
	clientCert          = flag.String("client_cert", "", "File path to the PEM encoding of the client's certificate chain")
	caRootCerts         = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
	testSKUName         = flag.String("sku", "sival", "The SKU configuration to use in the SPM configuration dir.")
	testSKUAuth         = flag.String("sku_auth", "test_password", "The SKU authorization password to use.")
	parallelClients     = flag.Int("parallel_clients", 0, "The total number of clients to run concurrently")
	totalCallsPerClient = flag.Int("total_calls_per_client", 0, "The total number of calls to execute during the load test")
	delayPerCall        = flag.Duration("delay_per_call", 10*time.Millisecond, "Delay between client calls used to emulate tester timeing. Default 100ms")
)

// clientTask encapsulates a client connection.
type clientTask struct {
	// id is a unique identifier assigned to the client instance.
	id int

	// results is a channel used to aggregate the results.
	results chan *callResult

	// delayPerCall is the delay applied between.
	delayPerCall time.Duration

	// client is the ProvisioningAppliance service client.
	client pbp.ProvisioningApplianceServiceClient

	// auth_token is the authentication token used to invoke ProvisioningAppliance
	// RPCs after a session has been opened and authenticated with the
	// ProvisioningAppliance.
	auth_token string
}

type callResult struct {
	// err is the error returned by the call, if any.
	err error
}

// setup creates a connection to the ProvisioningAppliance server, saving an
// authentication token provided by the ProvisioningAppliance. The connection
// supports the `enableTLS` flag and associated certificates.
func (c *clientTask) setup(ctx context.Context) error {
	opts := grpc.WithInsecure()
	if *enableTLS {
		credentials, err := grpconn.LoadClientCredentials(*caRootCerts, *clientCert, *clientKey)
		if err != nil {
			return err
		}
		opts = grpc.WithTransportCredentials(credentials)
	}

	conn, err := grpc.Dial(*paAddress, opts, grpc.WithBlock())
	if err != nil {
		return err
	}

	// Create new client contect with distinct user ID.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id))
	client_ctx := metadata.NewOutgoingContext(ctx, md)
	c.client = pbp.NewProvisioningApplianceServiceClient(conn)

	// Send request to PA and wait for response that contains auth_token.
	request := &pbp.InitSessionRequest{Sku: *testSKUName, SkuAuth: *testSKUAuth}
	response, err := c.client.InitSession(client_ctx, request)
	if err != nil {
		return err
	}
	c.auth_token = response.SkuSessionToken
	return nil
}

// tpm_run executes the CreateKeyAndCertRequest call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func (c *clientTask) tpm_run(ctx context.Context, numCalls int) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)
	request := &pbp.CreateKeyAndCertRequest{Sku: *testSKUName}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		_, err := c.client.CreateKeyAndCert(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{err: err}
		time.Sleep(c.delayPerCall)
	}
}

// ot_run executes the DeriveSymmetricKeys call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func (c *clientTask) ot_run(ctx context.Context, numCalls int) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.DeriveSymmetricKeysRequest{
		Sku: *testSKUName,
		Params: []*pbp.SymmetricKeygenParams{
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_LOW_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "test_unlock",
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_LOW_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "test_exit",
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_HIGH_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "rma,device_id",
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_HIGH_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_256_BITS,
				Diversifier: "was,device_id",
			},
		},
	}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		_, err := c.client.DeriveSymmetricKeys(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{err: err}
		time.Sleep(c.delayPerCall)
	}
}

// run executes the load test launching `numClients` clients and executing
// `numCalls` gRPC calls. Each client waits a duration of `delayPerCall`
// between calls.
func run(ctx context.Context, numClients, numCalls int, delayPerCall time.Duration) error {
	if numClients <= 0 {
		return fmt.Errorf("number of clients must be at least 1, got %d", numClients)
	}

	if numCalls <= 0 {
		return fmt.Errorf("number of class must be at least 1, got: %d", numCalls)
	}

	results := make(chan *callResult, maxBufferedCallResults)
	eg, ctx_start := errgroup.WithContext(ctx)

	log.Printf("Starting %d client instances", numClients)
	clients := make([]*clientTask, numClients)
	for i := 0; i < numClients; i++ {
		i := i
		eg.Go(func() error {
			clients[i] = &clientTask{
				id:           i,
				results:      results,
				delayPerCall: delayPerCall,
			}
			return clients[i].setup(ctx_start)
		})
	}
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("error during client setup: %v", err)
	}

	log.Printf("Starting load test with %d calls per client", numCalls)
	eg, ctx_test := errgroup.WithContext(ctx)
	for _, c := range clients {
		c := c
		eg.Go(func() error {
			switch *testSKUName {
			case "tpm_1":
				c.tpm_run(ctx_test, numCalls)
			case "sival":
				c.ot_run(ctx_test, numCalls)
			}
			return nil
		})
	}

	expectedNumCalls := numClients * numCalls
	errCount := 0
	eg.Go(func() error {
		for i := 0; i < expectedNumCalls; i++ {
			r := <-results
			if r.err != nil {
				errCount++
			}
		}
		if errCount > 0 {
			return fmt.Errorf("detected %d call errors", errCount)
		}
		return nil
	})

	return eg.Wait()
}

func main() {
	flag.Parse()
	if err := run(context.Background(), *parallelClients, *totalCallsPerClient, *delayPerCall); err != nil {
		log.Fatalf("Load test completed with errors: %v", err)
	}
	log.Print("Test PASS!")
}
