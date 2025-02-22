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
	"os"
	"strconv"
	"time"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	pbe "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
)

const (
	// Maximum number of buffered calls. This limits the number of concurrent
	// calls to ensure the program does not run out of memory.
	maxBufferedCallResults = 100000

	// Path to the TBS file used for testing the EndorseCerts call.
	diceTBSPath = "src/spm/services/testdata/tbs.der"
)

var (
	paAddress           = flag.String("pa_address", "", "the PA server address to connect to; required")
	enableTLS           = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	clientKey           = flag.String("client_key", "", "File path to the PEM encoding of the client's private key")
	clientCert          = flag.String("client_cert", "", "File path to the PEM encoding of the client's certificate chain")
	caRootCerts         = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
	testSKUAuth         = flag.String("sku_auth", "test_password", "The SKU authorization password to use.")
	parallelClients     = flag.Int("parallel_clients", 0, "The total number of clients to run concurrently")
	totalCallsPerMethod = flag.Int("total_calls_per_method", 0, "The total number of calls to execute during the load test")
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
	// id is the client identifier.
	id int
	// err is the error returned by the call, if any.
	err error
}

type clientGroup struct {
	clients []*clientTask
	results chan *callResult
}

// setup creates a connection to the ProvisioningAppliance server, saving an
// authentication token provided by the ProvisioningAppliance. The connection
// supports the `enableTLS` flag and associated certificates.
func (c *clientTask) setup(ctx context.Context, skuName string) error {
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

	// Create new client contact with distinct user ID.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id))
	client_ctx := metadata.NewOutgoingContext(ctx, md)
	c.client = pbp.NewProvisioningApplianceServiceClient(conn)

	// Send request to PA and wait for response that contains auth_token.
	request := &pbp.InitSessionRequest{Sku: skuName, SkuAuth: *testSKUAuth}
	response, err := c.client.InitSession(client_ctx, request)
	if err != nil {
		return err
	}
	c.auth_token = response.SkuSessionToken
	return nil
}

// callFunc is a function that executes a call to the ProvisioningAppliance
// service.
type callFunc func(context.Context, int, string, *clientTask)

// Executes the CreateKeyAndCertRequest call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func testTPMCreateKeyAndCertRequest(ctx context.Context, numCalls int, skuName string, c *clientTask) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)
	request := &pbp.CreateKeyAndCertRequest{Sku: skuName}

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

// Executes the DeriveSymmetricKeys call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func testOTDeriveSymmetricKeys(ctx context.Context, numCalls int, skuName string, c *clientTask) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.DeriveSymmetricKeysRequest{
		Sku: skuName,
		Params: []*pbp.SymmetricKeygenParams{
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_LOW_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "test_unlock",
				WrapSeed:    false,
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_LOW_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "test_exit",
				WrapSeed:    false,
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_HIGH_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS,
				Diversifier: "rma,device_id",
				WrapSeed:    false,
			},
			{
				Seed:        pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_HIGH_SECURITY,
				Type:        pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW,
				Size:        pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_256_BITS,
				Diversifier: "was,device_id",
				WrapSeed:    false,
			},
		},
	}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		_, err := c.client.DeriveSymmetricKeys(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{id: c.id, err: err}
		time.Sleep(c.delayPerCall)
	}
}

func testOTEndorseCerts(ctx context.Context, numCalls int, skuName string, c *clientTask, tbs []byte) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.EndorseCertsRequest{
		Sku: skuName,
		Bundles: []*pbp.EndorseCertBundle{
			{
				KeyParams: &pbc.SigningKeyParams{
					KeyLabel: "sku-sival-dice-priv-key-ver-0.0",
					Key: &pbc.SigningKeyParams_EcdsaParams{
						EcdsaParams: &pbe.EcdsaParams{
							HashType: pbcommon.HashType_HASH_TYPE_SHA256,
							Curve:    pbcommon.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P256,
							Encoding: pbe.EcdsaSignatureEncoding_ECDSA_SIGNATURE_ENCODING_DER,
						},
					},
				},
				Tbs: tbs,
			},
		},
	}
	for i := 0; i < numCalls; i++ {
		_, err := c.client.EndorseCerts(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{id: c.id, err: err}
		time.Sleep(c.delayPerCall)
	}
}

func NewEndorseCertTest() callFunc {
	filename, err := bazel.Runfile(diceTBSPath)
	if err != nil {
		log.Fatalf("unable to find file: %q, error: %v", diceTBSPath, err)
	}
	diceTBS, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to load file: %q, error: %v", filename, err)
	}
	return callFunc(func(ctx context.Context, numCalls int, skuName string, c *clientTask) {
		testOTEndorseCerts(ctx, numCalls, skuName, c, diceTBS)
	})
}

// Executes the RegisterDevice call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func testOTRegisterDevice(ctx context.Context, numCalls int, skuName string, c *clientTask) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.RegistrationRequest{
		DeviceData: &dpb.DeviceData{
			Sku: skuName,
			DeviceId: &dpb.DeviceId{
				HardwareOrigin: &dpb.HardwareOrigin{
					SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
					ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
					DeviceIdentificationNumber: uint64(c.id), // Each device ID must be unique.
				},
				SkuSpecific: make([]byte, dtd.DeviceIdSkuSpecificLenInBytes),
			},
			DeviceLifeCycle:       dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			WrappedRmaUnlockToken: make([]byte, dtd.WrappedRmaTokenLenInBytes),
			PersoTlvData:          make([]byte, dtd.MaxPersoTlvDataLenInBytes),
		},
	}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		_, err := c.client.RegisterDevice(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{id: c.id, err: err}
		time.Sleep(c.delayPerCall)
	}
}

func newClientGroup(ctx context.Context, numClients, numCalls int, delayPerCall time.Duration, skuName string) (*clientGroup, error) {
	if numClients <= 0 {
		return nil, fmt.Errorf("number of clients must be at least 1, got %d", numClients)
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
			return clients[i].setup(ctx_start, skuName)
		})
	}
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("error during client setup: %v", err)
	}
	return &clientGroup{
		clients: clients,
		results: results,
	}, nil
}

// run executes the load test launching `numClients` clients and executing
// `numCalls` gRPC calls. Each client waits a duration of `delayPerCall`
// between calls.
func run(ctx context.Context, cg *clientGroup, numCalls int, skuName string, test callFunc) error {
	if numCalls <= 0 {
		return fmt.Errorf("number of calls must be at least 1, got: %d", numCalls)
	}

	eg, ctx_test := errgroup.WithContext(ctx)
	for _, c := range cg.clients {
		c := c
		eg.Go(func() error {
			test(ctx_test, numCalls, skuName, c)
			return nil
		})
	}

	expectedNumCalls := len(cg.clients) * numCalls
	errCount := 0
	eg.Go(func() error {
		for i := 0; i < expectedNumCalls; i++ {
			r := <-cg.results
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

	type result struct {
		skuName  string
		testName string
		pass     bool
		msg      string
	}
	results := []result{}

	for _, t := range []struct {
		skuName  string
		testName string
		testFunc callFunc
	}{
		{
			skuName:  "tpm_1",
			testName: "TPM:CreateKeyAndCertRequest",
			testFunc: testTPMCreateKeyAndCertRequest,
		},
		{
			skuName:  "sival",
			testName: "OT:DeriveSymmetricKeys",
			testFunc: testOTDeriveSymmetricKeys,
		},
		{
			skuName:  "sival",
			testName: "OT:EndorseCerts",
			testFunc: NewEndorseCertTest(),
		},
		{
			skuName:  "sival",
			testName: "OT:RegisterDevice",
			testFunc: testOTRegisterDevice,
		},
	} {
		log.Printf("sku: %q", t.skuName)
		result := result{skuName: t.skuName, testName: t.testName}
		ctx := context.Background()
		cg, err := newClientGroup(ctx, *parallelClients, *totalCallsPerMethod, *delayPerCall, t.skuName)
		if err != nil {
			result.pass = false
			result.msg = fmt.Sprintf("failed to initialize client tasks: %v", err)
			continue
		}
		log.Printf("Running test %q", t.testName)
		if err := run(ctx, cg, *totalCallsPerMethod, t.skuName, t.testFunc); err != nil {
			result.pass = false
			result.msg = fmt.Sprintf("failed to execute test: %v", err)
			results = append(results, result)
			continue
		}
		result.pass = true
		result.msg = "PASS"
		results = append(results, result)
	}

	failed := 0
	for _, r := range results {
		if !r.pass {
			failed = failed + 1
		}
		log.Printf("sku: %q, test: %q, result: %v, msg: %q", r.skuName, r.testName, r.pass, r.msg)
	}
	if failed > 0 {
		log.Fatalf("Test FAIL!. %d tests failed", failed)
		return
	}
	log.Print("Test PASS!")
}
