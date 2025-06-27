// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main implementes Provisioning Appliance load test
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/lowRISC/opentitan-provisioning/src/ate"
	"github.com/lowRISC/opentitan-provisioning/src/ate/dututils"
	pbd "github.com/lowRISC/opentitan-provisioning/src/ate/proto/dut_commands_go_pb"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	pbe "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
	"github.com/lowRISC/opentitan-provisioning/src/utils/devid"
)

const (
	// Maximum number of buffered calls. This limits the number of concurrent
	// calls to ensure the program does not run out of memory.
	maxBufferedCallResults = 100000
)

var (
	caRootCerts     = flag.String("ca_root_certs", "", "File path to the PEM encoding of the CA root certificates")
	clientCert      = flag.String("client_cert", "", "File path to the PEM encoding of the client's certificate chain")
	clientKey       = flag.String("client_key", "", "File path to the PEM encoding of the client's private key")
	configDir       = flag.String("spm_config_dir", "", "Path to the SKU configuration directory.")
	enableTLS       = flag.Bool("enable_tls", false, "Enable mTLS secure channel; optional")
	hsmSOLibPath    = flag.String("hsm_so", "", "File path to the HSM's PKCS#11 shared library.")
	paAddress       = flag.String("pa_address", "", "the PA server address to connect to; required")
	parallelClients = flag.Int("parallel_clients", 1, "The total number of clients to run concurrently")
	skuNames        = flag.String("sku_names", "", "Comma-separated list of SKUs to test (e.g., sival,cr01,pi01,ti01). Required.")
	testSKUAuth     = flag.String("sku_auth", "test_password", "The SKU authorization password to use.")
	totalDuts       = flag.Int("total_duts", 1, "The total number of DUTs to process during the load test")
)

// clientTask encapsulates a client connection.
type clientTask struct {
	// id is a unique identifier assigned to the client instance.
	id int

	// results is a channel used to aggregate the results.
	results chan *callResult

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
	opts := []grpc.DialOption{grpc.WithBlock()}
	if *enableTLS {
		credentials, err := grpconn.LoadClientCredentials(*caRootCerts, *clientCert, *clientKey)
		if err != nil {
			return err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	conn, err := grpc.Dial(*paAddress, opts...)
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
type callFunc func(context.Context, int, string, *clientTask, []*dututils.Dut)

// buildTokensJSON builds a Tokens JSON object from the given tokens.
func buildTokensJSON(was, testUnlock, testExit *pbp.Token) ([]byte, error) {
	tokens := &pbd.TokensJSON{
		WaferAuthSecret:     make([]uint32, 8),
		TestUnlockTokenHash: make([]uint64, 2),
		TestExitTokenHash:   make([]uint64, 2),
	}
	for i := 0; i < 8; i++ {
		tokens.WaferAuthSecret[i] = binary.LittleEndian.Uint32(was.Token[i*4:])
	}
	for i := 0; i < 2; i++ {
		tokens.TestUnlockTokenHash[i] = binary.LittleEndian.Uint64(testUnlock.Token[i*8:])
		tokens.TestExitTokenHash[i] = binary.LittleEndian.Uint64(testExit.Token[i*8:])
	}
	return json.Marshal(tokens)
}

// buildRmaTokenJSON builds a RMA token JSON object from the given token.
func buildRmaTokenJSON(rmaToken *pbp.Token) ([]byte, error) {
	token := &pbd.RmaTokenJSON{
		Hash: make([]uint64, 2),
	}
	for i := 0; i < 2; i++ {
		token.Hash[i] = binary.LittleEndian.Uint64(rmaToken.Token[i*8:])
	}
	return json.Marshal(token)
}

// buildCaSubjectKeysJSON builds a CA subject keys JSON object from the given
// keys.
func buildCaSubjectKeysJSON(keys [][]byte) ([]byte, error) {
	if len(keys) != 2 {
		return nil, fmt.Errorf("expected 2 CA subject keys, got %d", len(keys))
	}
	caKeys := &pbd.CaSubjectKeysJSON{
		DiceAuthKeyKeyId: make([]uint32, 20),
		ExtAuthKeyKeyId:  make([]uint32, 20),
	}
	for i, b := range keys[0] {
		caKeys.DiceAuthKeyKeyId[i] = uint32(b)
	}
	for i, b := range keys[1] {
		caKeys.ExtAuthKeyKeyId[i] = uint32(b)
	}
	return json.Marshal(caKeys)
}

func processDut(ctx context.Context, c *clientTask, skuName string, dut *dututils.Dut) error {
	md := metadata.Pairs("user_id", strconv.Itoa(c.id), "authorization", c.auth_token)
	client_ctx := metadata.NewOutgoingContext(ctx, md)

	wasDiversifier, err := dut.WasDiversifier()
	if err != nil {
		return fmt.Errorf("failed to get WAS diversifier: %w", err)
	}

	// CP Stage
	cpTokensReq := &pbp.DeriveTokensRequest{
		Sku: skuName,
		Params: []*pbp.TokenParams{
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_HIGH_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_RAW,
				Size:        pbp.TokenSize_TOKEN_SIZE_256_BITS,
				Diversifier: wasDiversifier,
			},
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_LOW_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("test_unlock"),
			},
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_LOW_SECURITY,
				Type:        pbp.TokenType_TOKEN_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("test_exit"),
			},
		},
	}
	cpTokens, err := c.client.DeriveTokens(client_ctx, cpTokensReq)
	if err != nil {
		return fmt.Errorf("failed to derive CP tokens: %w", err)
	}
	tokensJSON, err := buildTokensJSON(cpTokens.Tokens[0], cpTokens.Tokens[1], cpTokens.Tokens[2])
	if err != nil {
		return fmt.Errorf("failed to build tokens JSON: %w", err)
	}
	if err := dut.ProcessTokensJSON(tokensJSON); err != nil {
		return fmt.Errorf("DUT failed to process tokens JSON: %w", err)
	}
	if _, err := dut.GenerateCpDeviceIDJson(); err != nil {
		return fmt.Errorf("DUT failed to generate device ID JSON: %w", err)
	}

	// FT Stage
	rmaTokenReq := &pbp.DeriveTokensRequest{
		Sku: skuName,
		Params: []*pbp.TokenParams{
			{
				Seed:        pbp.TokenSeed_TOKEN_SEED_KEYGEN,
				Type:        pbp.TokenType_TOKEN_TYPE_HASHED_OT_LC_TOKEN,
				Size:        pbp.TokenSize_TOKEN_SIZE_128_BITS,
				Diversifier: []byte("rma,device_id"),
				WrapSeed:    true,
			},
		},
	}
	rmaTokenResp, err := c.client.DeriveTokens(client_ctx, rmaTokenReq)
	if err != nil {
		return fmt.Errorf("failed to derive RMA token: %w", err)
	}
	rmaTokenJSON, err := buildRmaTokenJSON(rmaTokenResp.Tokens[0])
	if err != nil {
		return fmt.Errorf("failed to build RMA token JSON: %w", err)
	}
	if err := dut.ProcessRmaTokenJSON(rmaTokenJSON); err != nil {
		return fmt.Errorf("DUT failed to process RMA token JSON: %w", err)
	}
	dut.SetWrappedRmaTokenSeed(rmaTokenResp.Tokens[0].WrappedSeed)

	caKeysReq := &pbp.GetCaSubjectKeysRequest{
		Sku:        skuName,
		CertLabels: []string{"UDS", "EXT"},
	}
	caKeysResp, err := c.client.GetCaSubjectKeys(client_ctx, caKeysReq)
	if err != nil {
		return fmt.Errorf("failed to get CA subject keys: %w", err)
	}
	caKeysJSON, err := buildCaSubjectKeysJSON(caKeysResp.KeyIds)
	if err != nil {
		return fmt.Errorf("failed to build CA subject keys JSON: %w", err)
	}
	if err := dut.ProcessCaSubjectKeysJSON(caKeysJSON); err != nil {
		return fmt.Errorf("DUT failed to process CA subject keys JSON: %w", err)
	}

	persoBlobJSON, err := dut.GeneratePersoBlob()
	if err != nil {
		return fmt.Errorf("DUT failed to generate perso blob: %w", err)
	}
	var persoBlobFromDUT pbd.PersoBlobJSON
	if err := json.Unmarshal(persoBlobJSON, &persoBlobFromDUT); err != nil {
		return fmt.Errorf("failed to unmarshal perso blob from DUT: %w", err)
	}
	blobBytes := make([]byte, persoBlobFromDUT.NextFree)
	for i := 0; i < int(persoBlobFromDUT.NextFree); i++ {
		blobBytes[i] = byte(persoBlobFromDUT.Body[i])
	}
	persoBlob, err := ate.UnpackPersoBlob(blobBytes)
	if err != nil {
		return fmt.Errorf("failed to unpack perso blob from DUT: %w", err)
	}

	endorseReq := &pbp.EndorseCertsRequest{
		Sku:         skuName,
		Diversifier: wasDiversifier,
		Signature:   persoBlob.Signature.Raw[:],
		Bundles:     []*pbp.EndorseCertBundle{},
	}
	for _, tbsCert := range persoBlob.X509TbsCerts {
		endorseReq.Bundles = append(endorseReq.Bundles, &pbp.EndorseCertBundle{
			KeyParams: &pbc.SigningKeyParams{
				KeyLabel: tbsCert.KeyLabel,
				Key: &pbc.SigningKeyParams_EcdsaParams{
					EcdsaParams: &pbe.EcdsaParams{
						HashType: pbcommon.HashType_HASH_TYPE_SHA256,
						Curve:    pbcommon.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P256,
						Encoding: pbe.EcdsaSignatureEncoding_ECDSA_SIGNATURE_ENCODING_DER,
					},
				},
			},
			Tbs: tbsCert.Tbs,
		})
	}
	endorsedCerts, err := c.client.EndorseCerts(client_ctx, endorseReq)
	if err != nil {
		return fmt.Errorf("failed to endorse certs: %w", err)
	}

	var endorsedCertsForDut []ate.EndorseCertResponse
	for _, cert := range endorsedCerts.Certs {
		endorsedCertsForDut = append(endorsedCertsForDut, ate.EndorseCertResponse{
			KeyLabel: cert.KeyLabel,
			Cert:     cert.Cert.Blob,
		})
	}
	persoBlobToDut, err := ate.BuildPersoBlob(&ate.PersoBlob{X509Certs: endorsedCertsForDut})
	if err != nil {
		return fmt.Errorf("failed to build perso blob for DUT: %w", err)
	}

	persoBlobToDutForJSON := &pbd.PersoBlobJSON{
		NumObjs:  uint32(len(endorsedCertsForDut)),
		NextFree: uint32(len(persoBlobToDut)),
		Body:     make([]uint32, dututils.KPersoBlobMaxSize),
	}
	for i, b := range persoBlobToDut {
		persoBlobToDutForJSON.Body[i] = uint32(b)
	}
	persoBlobToDutJSON, err := json.Marshal(persoBlobToDutForJSON)
	if err != nil {
		return fmt.Errorf("failed to marshal perso blob for DUT: %w", err)
	}

	if err := dut.StoreEndorsedCerts(persoBlobToDutJSON); err != nil {
		return fmt.Errorf("DUT failed to store endorsed certs: %w", err)
	}

	deviceData, err := devid.FromRawBytes(dut.DeviceID.Raw[:])
	if err != nil {
		return fmt.Errorf("failed to convert device ID from raw bytes: %w", err)
	}

	persoTlv, numObjs, err := dut.GeneratePersoTlv()
	if err != nil {
		return fmt.Errorf("failed to generate perso TLV: %w", err)
	}

	regReq := &pbp.RegistrationRequest{
		DeviceData: &dpb.DeviceData{
			Sku:                skuName,
			DeviceId:           deviceData,
			DeviceLifeCycle:    dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
			PersoTlvData:       persoTlv,
			NumPersoTlvObjects: numObjs,
		},
	}
	if _, err := c.client.RegisterDevice(client_ctx, regReq); err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}

	return nil
}

func testManufacturingFlow(ctx context.Context, numDuts int, skuName string, c *clientTask, duts []*dututils.Dut) {
	for i := 0; i < numDuts; i++ {
		dut := duts[i]
		log.Printf("client %d processing DUT %x", c.id, dut.DeviceID.Raw[:])
		err := processDut(ctx, c, skuName, dut)
		c.results <- &callResult{id: c.id, err: err}
	}
}

func newClientGroup(ctx context.Context, numClients int, skuName string) (*clientGroup, error) {
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
				id:      i,
				results: results,
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

func run(ctx context.Context, cg *clientGroup, numDutsPerClient int, skuName string, test callFunc, allDuts []*dututils.Dut) (int, error) {
	if numDutsPerClient <= 0 && len(allDuts) > 0 {
		return 0, fmt.Errorf("number of DUTs must be at least 1, got: %d", len(allDuts))
	}

	eg, ctx_test := errgroup.WithContext(ctx)
	for i, c := range cg.clients {
		client := c
		start := i * numDutsPerClient
		end := start + numDutsPerClient
		if end > len(allDuts) {
			end = len(allDuts)
		}
		if start >= end {
			continue
		}
		clientDuts := allDuts[start:end]

		eg.Go(func() error {
			test(ctx_test, len(clientDuts), skuName, client, clientDuts)
			return nil
		})
	}

	// Wait for all clients to finish in a separate goroutine.
	clientErrChan := make(chan error)
	go func() {
		clientErrChan <- eg.Wait()
	}()

	// Collect results.
	errCount := 0
	errorMsgs := []string{}
	expectedNumCalls := len(allDuts)
	for i := 0; i < expectedNumCalls; i++ {
		r := <-cg.results
		if r.err != nil {
			errorMsgs = append(errorMsgs, fmt.Sprintf("client %d: %v", r.id, r.err))
			log.Printf("client %d: %v", r.id, r.err)
			errCount++
		}
	}

	// Check for errors from clients.
	if err := <-clientErrChan; err != nil {
		return errCount, err
	}

	if errCount > 0 {
		return errCount, fmt.Errorf("detected %d call errors. errors: \n%s", errCount, strings.Join(errorMsgs, "\n"))
	}

	return 0, nil
}

func main() {
	flag.Parse()

	if *skuNames == "" {
		log.Fatalf("sku_names is required")
	}
	if *totalDuts == 0 {
		log.Fatalf("total_duts must be greater than 0")
	}

	type result struct {
		skuName  string
		testName string
		pass     bool
		msg      string
		rate     float64
		duration time.Duration
		numDuts  int
	}
	results := []result{}
	parsedSkuNames := strings.Split(*skuNames, ",")

	opts := skumgr.Options{
		ConfigDir:    *configDir,
		HSMSOLibPath: *hsmSOLibPath,
	}

	for _, skuName := range parsedSkuNames {
		log.Printf("Processing SKU: %q", skuName)

		duts := make([]*dututils.Dut, *totalDuts)
		for i := 0; i < *totalDuts; i++ {
			dut, err := dututils.NewDut(opts, skuName)
			if err != nil {
				log.Fatalf("failed to create DUT %d for SKU %q: %v", i, skuName, err)
			}
			if err := dut.BuildTbsCerts(); err != nil {
				log.Fatalf("failed to build TBS certificates for DUT %d for SKU %q: %v", i, skuName, err)
			}
			duts[i] = dut
		}
		log.Printf("Created %d DUTs for SKU %q", len(duts), skuName)

		tests := []struct {
			testName string
			testFunc callFunc
		}{
			{
				testName: "ManufacturingFlow",
				testFunc: testManufacturingFlow,
			},
		}

		for _, t := range tests {
			log.Printf("sku: %q, test: %q", skuName, t.testName)
			currentResult := result{skuName: skuName, testName: t.testName}
			ctx := context.Background()
			cg, err := newClientGroup(ctx, *parallelClients, skuName)
			if err != nil {
				currentResult.pass = false
				currentResult.msg = fmt.Sprintf("failed to initialize client tasks: %v", err)
				results = append(results, currentResult)
				continue
			}

			dutsPerClient := *totalDuts / *parallelClients
			if *totalDuts%*parallelClients != 0 {
				dutsPerClient++
			}

			log.Printf("Running test %q for SKU %q", t.testName, skuName)
			startTime := time.Now()
			errCount, err := run(ctx, cg, dutsPerClient, skuName, t.testFunc, duts)
			elapsedTime := time.Since(startTime)
			if err != nil {
				currentResult.pass = false
				currentResult.msg = fmt.Sprintf("failed to execute test (failure count: %d): %v", errCount, err)
				results = append(results, currentResult)
				continue
			}

			rate := float64(*totalDuts) / elapsedTime.Hours()

			currentResult.pass = true
			currentResult.msg = "PASS"
			currentResult.rate = rate
			currentResult.duration = elapsedTime
			currentResult.numDuts = *totalDuts
			results = append(results, currentResult)
		}
	}

	failed := 0
	for _, r := range results {
		if !r.pass {
			failed++
		}
		log.Printf("sku: %q", r.skuName)
		log.Printf("   test: %q, result: %t", r.testName, r.pass)
		log.Printf("   rate: %.2f chips/hour, duration: %.2fs, numDuts: %d", r.rate, r.duration.Seconds(), r.numDuts)
		if strings.Contains(r.msg, "\n") {
			log.Print("   msg:")
			for _, line := range strings.Split(r.msg, "\n") {
				log.Printf("     %s", line)
			}
		} else {
			log.Printf("   msg: %q", r.msg)
		}
	}
	if failed > 0 {
		log.Fatalf("Test FAIL!. %d tests failed", failed)
	}
	log.Print("Test PASS!")
}
