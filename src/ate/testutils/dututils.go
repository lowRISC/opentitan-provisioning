// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package dututils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/ate"
	pbd "github.com/lowRISC/opentitan-provisioning/src/ate/proto/dut_commands_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/testutils/tbsgen"
	"github.com/lowRISC/opentitan-provisioning/src/utils/devid"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
)

// From ate_api.h
const KPersoBlobMaxSize = 8192

// Simulated hardware delays
const (
	GenerateCpDeviceIDJsonDelay   = 10 * time.Millisecond
	GeneratePersoBlobDelay        = 50 * time.Millisecond
	StoreEndorsedCertsDelay       = 300 * time.Millisecond
	ProcessTokensJSONDelay        = 5 * time.Millisecond
	ProcessRmaTokenJSONDelay      = 5 * time.Millisecond
	ProcessCaSubjectKeysJSONDelay = 5 * time.Millisecond
)

// Dut emulates an OpenTitan device during provisioning.
type Dut struct {
	skuMgr        *skumgr.Manager
	opts          skumgr.Options
	skuName       string
	privKey       *ecdsa.PrivateKey
	DeviceID      *ate.DeviceIDBytes
	persoBlob     *ate.PersoBlob
	endorsedCerts []ate.EndorseCertResponse

	// Cached tokens
	waferAuthSecret     []byte
	testUnlockToken     []byte
	testExitToken       []byte
	rmaTokenHash        []byte
	wrappedRmaTokenSeed []byte
	caSubjectKeyIds     [][]byte
}

// NewDut creates and initializes a new emulated DUT.
func NewDut(opts skumgr.Options, skuName string) (*Dut, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	devIdProto := &dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
			ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
			DeviceIdentificationNumber: mrand.Uint64(),
		},
		SkuSpecific: make([]byte, dtd.DeviceIdSkuSpecificLenInBytes),
	}
	if _, err := rand.Read(devIdProto.SkuSpecific); err != nil {
		return nil, fmt.Errorf("failed to generate SKU specific data: %w", err)
	}
	dBytes, err := devid.DeviceIDToRawBytes(devIdProto)
	if err != nil {
		return nil, fmt.Errorf("unable to convert device ID to raw bytes: %v", err)
	}
	var deviceID ate.DeviceIDBytes
	copy(deviceID.Raw[:], dBytes)

	return &Dut{
		skuMgr:              skumgr.NewManager(opts),
		opts:                opts,
		skuName:             skuName,
		privKey:             privKey,
		DeviceID:            &deviceID,
		waferAuthSecret:     []byte{},
		testUnlockToken:     []byte{},
		testExitToken:       []byte{},
		rmaTokenHash:        []byte{},
		wrappedRmaTokenSeed: []byte{},
		caSubjectKeyIds:     [][]byte{},
	}, nil
}

// GenerateCpDeviceIDJson generates a device ID and returns it as a JSON payload.
func (d *Dut) GenerateCpDeviceIDJson() ([]byte, error) {
	time.Sleep(GenerateCpDeviceIDJsonDelay)
	// The CP device ID is the hardware origin part of the full device ID,
	// which is the first 16 bytes.
	hwOriginBytes := d.DeviceID.Raw[0:16]
	deviceID := &pbd.DeviceIdJSON{
		CpDeviceId: make([]uint32, 4),
	}
	for i := 0; i < 4; i++ {
		deviceID.CpDeviceId[i] = binary.LittleEndian.Uint32(hwOriginBytes[i*4:])
	}
	return json.Marshal(deviceID)
}

// WasDiversifier returns a 48 byte diversifier for the DUT.
func (d *Dut) WasDiversifier() ([]byte, error) {
	hwOrigin := d.DeviceID.Raw[0:16]
	// The ATE DLL API requires a diversifier of 48 bytes. We emulate this by creating
	// a 48 byte slice and appending the hardware ID to it. The first 3 bytes are
	// "was" and the rest are the hardware ID.
	dID := make([]byte, 48)
	copy(dID, []byte("was"))
	copy(dID[3:], hwOrigin)
	return dID, nil
}

// StoreEndorsedCerts unpacks a perso blob with endorsed certs and stores them.
func (d *Dut) StoreEndorsedCerts(persoBlobJSON []byte) error {
	time.Sleep(StoreEndorsedCertsDelay)
	var blob pbd.PersoBlobJSON
	if err := json.Unmarshal(persoBlobJSON, &blob); err != nil {
		return fmt.Errorf("failed to unmarshal perso blob JSON: %w", err)
	}
	if blob.NextFree > uint32(len(blob.Body)) {
		return fmt.Errorf("next_free (%d) is larger than body size (%d)", blob.NextFree, len(blob.Body))
	}
	blobBytes := make([]byte, blob.NextFree)
	for i := 0; i < int(blob.NextFree); i++ {
		v := blob.Body[i]
		if v > 255 {
			return fmt.Errorf("invalid byte value in perso blob body: %d", v)
		}
		blobBytes[i] = byte(v)
	}

	persoBlob, err := ate.UnpackPersoBlob(blobBytes)
	if err != nil {
		return fmt.Errorf("failed to unpack perso blob: %w", err)
	}
	d.endorsedCerts = persoBlob.X509Certs
	return nil
}

// ProcessTokensJSON takes a JSON payload, unmarshals it, and caches the tokens.
func (d *Dut) ProcessTokensJSON(tokensJSON []byte) error {
	time.Sleep(ProcessTokensJSONDelay)
	var tokens pbd.TokensJSON
	if err := json.Unmarshal(tokensJSON, &tokens); err != nil {
		return fmt.Errorf("failed to unmarshal tokens JSON: %w", err)
	}

	// wafer_auth_secret must contain 8 uint32 values.
	if len(tokens.WaferAuthSecret) != 8 {
		return fmt.Errorf("expected 8 uint32 values for wafer_auth_secret, got %d", len(tokens.WaferAuthSecret))
	}
	d.waferAuthSecret = make([]byte, 32)
	for i, v := range tokens.WaferAuthSecret {
		binary.BigEndian.PutUint32(d.waferAuthSecret[i*4:], v)
	}

	// test_unlock_token_hash must contain 2 uint64 values.
	if len(tokens.TestUnlockTokenHash) != 2 {
		return fmt.Errorf("expected 2 uint64 values for test_unlock_token_hash, got %d", len(tokens.TestUnlockTokenHash))
	}
	d.testUnlockToken = make([]byte, 16)
	for i, v := range tokens.TestUnlockTokenHash {
		binary.BigEndian.PutUint64(d.testUnlockToken[i*8:], v)
	}

	// test_exit_token_hash must contain 2 uint64 values.
	if len(tokens.TestExitTokenHash) != 2 {
		return fmt.Errorf("expected 2 uint64 values for test_exit_token_hash, got %d", len(tokens.TestExitTokenHash))
	}
	d.testExitToken = make([]byte, 16)
	for i, v := range tokens.TestExitTokenHash {
		binary.BigEndian.PutUint64(d.testExitToken[i*8:], v)
	}

	return nil
}

// ProcessRmaTokenJSON takes a JSON payload, unmarshals it, and caches the RMA token.
func (d *Dut) ProcessRmaTokenJSON(rmaTokenJSON []byte) error {
	time.Sleep(ProcessRmaTokenJSONDelay)
	var token pbd.RmaTokenJSON
	if err := json.Unmarshal(rmaTokenJSON, &token); err != nil {
		return fmt.Errorf("failed to unmarshal RMA token JSON: %w", err)
	}

	// hash must contain 2 uint64 values.
	if len(token.Hash) != 2 {
		return fmt.Errorf("expected 2 uint64 values for rma_token_hash, got %d", len(token.Hash))
	}
	d.rmaTokenHash = make([]byte, 16)
	for i, v := range token.Hash {
		binary.BigEndian.PutUint64(d.rmaTokenHash[i*8:], v)
	}

	return nil
}

// ProcessCaSubjectKeysJSON takes a JSON payload, unmarshals it, and caches the CA subject keys.
func (d *Dut) ProcessCaSubjectKeysJSON(caKeysJSON []byte) error {
	time.Sleep(ProcessCaSubjectKeysJSONDelay)
	var keys pbd.CaSubjectKeysJSON
	if err := json.Unmarshal(caKeysJSON, &keys); err != nil {
		return fmt.Errorf("failed to unmarshal CA keys JSON: %w", err)
	}

	// dice_auth_key_key_id must contain 20 bytes.
	if len(keys.DiceAuthKeyKeyId) != 20 {
		return fmt.Errorf("expected 20 bytes for dice_auth_key_key_id, got %d", len(keys.DiceAuthKeyKeyId))
	}
	diceKey := make([]byte, 20)
	for i, v := range keys.DiceAuthKeyKeyId {
		if v > 255 {
			return fmt.Errorf("invalid byte value in dice_auth_key_key_id: %d", v)
		}
		diceKey[i] = byte(v)
	}

	// ext_auth_key_key_id must contain 20 bytes.
	if len(keys.ExtAuthKeyKeyId) != 20 {
		return fmt.Errorf("expected 20 bytes for ext_auth_key_key_id, got %d", len(keys.ExtAuthKeyKeyId))
	}
	extKey := make([]byte, 20)
	for i, v := range keys.ExtAuthKeyKeyId {
		if v > 255 {
			return fmt.Errorf("invalid byte value in ext_auth_key_key_id: %d", v)
		}
		extKey[i] = byte(v)
	}

	d.caSubjectKeyIds = [][]byte{diceKey, extKey}
	return nil
}

// SetWrappedRmaTokenSeed caches the wrapped RMA token seed.
func (d *Dut) SetWrappedRmaTokenSeed(seed []byte) {
	d.wrappedRmaTokenSeed = seed
}

// GeneratePersoBlob builds a personalization blob containing TBS certificates.
func (d *Dut) GeneratePersoBlob() ([]byte, error) {
	time.Sleep(GeneratePersoBlobDelay)
	certLabels := []string{"UDS"}
	tbsCerts, _, err := tbsgen.BuildTestTBSCerts(d.opts, d.skuName, certLabels)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TBS certificates for SKU %q: %v", d.skuName, err)
	}

	var tbsBytesToSign bytes.Buffer
	var x509TbsCerts []ate.EndorseCertRequest
	for label, tbs := range tbsCerts {
		x509TbsCerts = append(x509TbsCerts, ate.EndorseCertRequest{
			KeyLabel: label,
			Tbs:      tbs,
		})
		tbsBytesToSign.Write(tbs)
	}

	// Create a signature over the TBS certs.
	var signature ate.EndorseCertSignature
	if len(d.waferAuthSecret) != 32 {
		return nil, fmt.Errorf("wafer authentication secret not available to sign TBS certificates")
	}

	mac := hmac.New(sha256.New, d.waferAuthSecret)
	mac.Write(tbsBytesToSign.Bytes())
	copy(signature.Raw[:], mac.Sum(nil))

	d.persoBlob = &ate.PersoBlob{
		DeviceID:     d.DeviceID,
		Signature:    &signature,
		X509TbsCerts: x509TbsCerts,
		X509Certs:    []ate.EndorseCertResponse{}, // No endorsed certs yet.
		Seeds:        []ate.Seed{},                // No seeds for now.
	}
	blobBytes, err := ate.BuildPersoBlob(d.persoBlob)
	if err != nil {
		return nil, err
	}

	numObjs := len(d.persoBlob.X509TbsCerts) + len(d.persoBlob.X509Certs) + len(d.persoBlob.Seeds)
	if d.persoBlob.DeviceID != nil {
		numObjs++
	}
	if d.persoBlob.Signature != nil {
		numObjs++
	}

	persoBlobJSON := &pbd.PersoBlobJSON{
		NumObjs:  uint32(numObjs),
		NextFree: uint32(len(blobBytes)),
		Body:     make([]uint32, KPersoBlobMaxSize),
	}
	for i, b := range blobBytes {
		persoBlobJSON.Body[i] = uint32(b)
	}
	return json.Marshal(persoBlobJSON)
}
