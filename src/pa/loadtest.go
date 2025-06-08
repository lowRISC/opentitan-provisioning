// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implementes Provisioning Appliance load test
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	pbe "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/testutils/tbsgen"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"github.com/lowRISC/opentitan-provisioning/src/utils/devid"
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
	testSKUAuth         = flag.String("sku_auth", "test_password", "The SKU authorization password to use.")
	skuNames            = flag.String("sku_names", "", "Comma-separated list of SKUs to test (e.g., sival,cr01,pi01,ti01). Required.")
	parallelClients     = flag.Int("parallel_clients", 0, "The total number of clients to run concurrently")
	totalCallsPerMethod = flag.Int("total_calls_per_method", 0, "The total number of calls to execute during the load test")
	delayPerCall        = flag.Duration("delay_per_call", 10*time.Millisecond, "Delay between client calls used to emulate tester timeing. Default 100ms")
	configDir           = flag.String("spm_config_dir", "", "Path to the SKU configuration directory.")
	hsmSOLibPath        = flag.String("hsm_so", "", "File path to the HSM's PKCS#11 shared library.")
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

// Executes the DeriveTokens call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func testOTDeriveTokens(ctx context.Context, numCalls int, skuName string, c *clientTask) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.DeriveTokensRequest{
		Sku: skuName,
		Params: []*pbp.TokenParams{
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_LOW_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_RAW,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("test_unlock"),
				WrapSeed:    false,
			},
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_LOW_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_RAW,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("test_exit"),
				WrapSeed:    false,
			},
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_KEYGEN,
				Type:        pbp.TokenType_TOKEN_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("rma,device_id"),
				WrapSeed:    true,
			},
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_HIGH_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_RAW,
				Size:        pbp.TokenSize_TOKEN_SIZE_256_BITS,
				Diversifier: []byte("was,device_id"),
				WrapSeed:    false,
			},
		},
	}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		_, err := c.client.DeriveTokens(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		c.results <- &callResult{id: c.id, err: err}
		time.Sleep(c.delayPerCall)
	}
}

// Executes the GetCaSerialNumbers call for a `numCalls` total and
// produces a `callResult` which is sent to the `clientTask.results` channel.
func testOTGetCaSerialNumbers(ctx context.Context, numCalls int, skuName string, c *clientTask) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.GetCaSerialNumbersRequest{
		Sku:        skuName,
		CertLabels: []string{"SigningKey/Dice/v0"},
	}

	// Send request to PA.
	for i := 0; i < numCalls; i++ {
		r, err := c.client.GetCaSerialNumbers(client_ctx, request)
		if err != nil {
			log.Printf("error: client id: %d, error: %v", c.id, err)
		}
		for j, label := range request.CertLabels {
			log.Printf("CA %q serial number: 0x%s", label, hex.EncodeToString(r.SerialNumbers[j]))
		}
		c.results <- &callResult{id: c.id, err: err}
		time.Sleep(c.delayPerCall)
	}
}

func testOTEndorseCerts(ctx context.Context, numCalls int, skuName string, c *clientTask, tbs, dID, signature []byte) {
	// Prepare request and auth token.
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	request := &pbp.EndorseCertsRequest{
		Sku:         skuName,
		Diversifier: dID,
		Signature:   signature,
		Bundles: []*pbp.EndorseCertBundle{
			{
				KeyParams: &pbc.SigningKeyParams{
					KeyLabel: "SigningKey/Dice/v0",
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

func NewEndorseCertTest(tbs []byte) callFunc {
	d := &dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
			ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
			DeviceIdentificationNumber: rand.Uint64(), // Each device ID must be unique.
		},
		SkuSpecific: make([]byte, dtd.DeviceIdSkuSpecificLenInBytes),
	}
	dBytes, err := devid.HardwareOriginToRawBytes(d.HardwareOrigin)
	if err != nil {
		log.Fatalf("unable to convert device ID to raw bytes: %v", err)
	}

	// The ATE DLL API requires a diversifier of 48 bytes. We emulate this by creating
	// a 48 byte slice and appending the hardware ID to it. The first 3 bytes are
	// "was" and the rest are the hardware ID.
	dID := make([]byte, 48)
	copy(dID, []byte("was"))
	copy(dID[3:], dBytes)

	return callFunc(func(ctx context.Context, numCalls int, skuName string, c *clientTask) {
		// Prepare request and auth token.
		md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
		client_ctx := metadata.NewOutgoingContext(ctx, md)

		// Obtain the WAS token and calculate the signature over the TBS,
		// emulating the behavior of the device.
		result, err := c.client.DeriveTokens(client_ctx, &pbp.DeriveTokensRequest{
			Sku: skuName,
			Params: []*pbp.TokenParams{
				{
					Seed:        pbp.TokenSeed_TOKEN_SEED_HIGH_SECURITY,
					Type:        pbp.TokenType_TOKEN_TYPE_RAW,
					Size:        pbp.TokenSize_TOKEN_SIZE_256_BITS,
					Diversifier: dID,
					WrapSeed:    false,
				},
			},
		})
		if err != nil {
			log.Fatalf("failed to get WAS token: %v", err)
		}
		if len(result.Tokens) != 1 {
			log.Fatalf("expected 1 token, got %d", len(result.Tokens))
		}
		mac := hmac.New(sha256.New, result.Tokens[0].Token)
		mac.Write(tbs)
		sig := mac.Sum(nil)

		testOTEndorseCerts(ctx, numCalls, skuName, c, tbs, dID, sig)
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
					DeviceIdentificationNumber: rand.Uint64(), // Each device ID must be unique.
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
		// Since the device IDs need to be unique, subsequent calls with the same ID will
		// result in an already exists error.
		request.DeviceData.DeviceId.HardwareOrigin.DeviceIdentificationNumber = rand.Uint64()
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

	if *skuNames == "" {
		log.Fatalf("sku_names is required")
	}

	type result struct {
		skuName  string
		testName string
		pass     bool
		msg      string
	}
	results := []result{}
	parsedSkuNames := strings.Split(*skuNames, ",")

	for _, skuName := range parsedSkuNames {
		log.Printf("Processing SKU: %q", skuName)

		opts := skumgr.Options{
			ConfigDir:    *configDir,
			HSMSOLibPath: *hsmSOLibPath,
		}
		certLabels := []string{"SigningKey/Dice/v0"}
		tbsCerts, _, err := tbsgen.BuildTestTBSCerts(opts, skuName, certLabels)
		if err != nil {
			log.Fatalf("failed to generate TBS certificates for SKU %q: %v", skuName, err)
		}
		log.Printf("Generated TBS certs for SKU %q", skuName)

		tests := []struct {
			testName string
			testFunc callFunc
		}{
			{
				testName: "OT:DeriveTokens",
				testFunc: testOTDeriveTokens,
			},
			{
				testName: "OT:GetCaSerialNumbers",
				testFunc: testOTGetCaSerialNumbers,
			},
			{
				testName: "OT:EndorseCerts",
				testFunc: NewEndorseCertTest(tbsCerts["SigningKey/Dice/v0"]),
			},
			{
				testName: "OT:RegisterDevice",
				testFunc: testOTRegisterDevice,
			},
		}

		for _, t := range tests {
			log.Printf("sku: %q, test: %q", skuName, t.testName)
			currentResult := result{skuName: skuName, testName: t.testName}
			ctx := context.Background()
			cg, err := newClientGroup(ctx, *parallelClients, *totalCallsPerMethod, *delayPerCall, skuName)
			if err != nil {
				currentResult.pass = false
				currentResult.msg = fmt.Sprintf("failed to initialize client tasks: %v", err)
				results = append(results, currentResult)
				continue
			}
			log.Printf("Running test %q for SKU %q", t.testName, skuName)
			if err := run(ctx, cg, *totalCallsPerMethod, skuName, t.testFunc); err != nil {
				currentResult.pass = false
				currentResult.msg = fmt.Sprintf("failed to execute test: %v", err)
				results = append(results, currentResult)
				continue
			}
			currentResult.pass = true
			currentResult.msg = "PASS"
			results = append(results, currentResult)
		}
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
