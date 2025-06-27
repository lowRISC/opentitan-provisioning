// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package dututils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"log"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/ate"
	pbd "github.com/lowRISC/opentitan-provisioning/src/ate/proto/dut_commands_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
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

// Constants for various data structures.
const (
	// From src/proto/device_id.proto
	cpDeviceIDLenInBytes = 16
	// The ATE DLL API requires a diversifier of 48 bytes.
	wasDiversifierLen = 48
	// Wafer authentication secret is 32 bytes (8 words).
	waferAuthSecretLenInWords = 8
	waferAuthSecretLenInBytes = 32
	// Test/RMA tokens are 16 bytes (2 uint64s).
	tokenHashLenInWords = 2
	tokenHashLenInBytes = 16
	// Authority Key IDs are 20 bytes (SHA1 hash).
	authKeyIDLen = 20
)

// Dut emulates an OpenTitan device during provisioning.
type Dut struct {
	skuMgr        *skumgr.Manager
	skuConfig     *skucfg.Config
	skuName       string
	DeviceID      *ate.DeviceIDBytes
	privKeys      map[string]*ecdsa.PrivateKey
	persoBlob     *ate.PersoBlob
	endorsedCerts []ate.EndorseCertResponse
	tbsCerts      map[string][]byte
	certChainDiceLeaf string

	// Cached tokens
	waferAuthSecret     []byte
	testUnlockToken     []byte
	testExitToken       []byte
	rmaTokenHash        []byte
	wrappedRmaTokenSeed []byte
	caSubjectKeyIds     [][]byte
}

// parseWaferAuthSecret converts a slice of uint32 words to a byte slice.
func parseWaferAuthSecret(words []uint32, name string) ([]byte, error) {
	if len(words) != waferAuthSecretLenInWords {
		return nil, fmt.Errorf("expected %d uint32 values for %s, got %d", waferAuthSecretLenInWords, name, len(words))
	}
	b := make([]byte, waferAuthSecretLenInBytes)
	for i, v := range words {
		binary.BigEndian.PutUint32(b[i*4:], v)
	}
	return b, nil
}

// parseTokenHash converts a slice of uint64s to a byte slice.
func parseTokenHash(u64s []uint64, name string) ([]byte, error) {
	if len(u64s) != tokenHashLenInWords {
		return nil, fmt.Errorf("expected %d uint64 values for %s, got %d", tokenHashLenInWords, name, len(u64s))
	}
	b := make([]byte, tokenHashLenInBytes)
	for i, v := range u64s {
		binary.BigEndian.PutUint64(b[i*8:], v)
	}
	return b, nil
}

// parseAuthKeyID converts a slice of ints to a byte slice.
func parseAuthKeyID(ints []uint32, name string) ([]byte, error) {
	if len(ints) != authKeyIDLen {
		return nil, fmt.Errorf("expected %d bytes for %s, got %d", authKeyIDLen, name, len(ints))
	}
	b := make([]byte, authKeyIDLen)
	for i, v := range ints {
		if v > 255 {
			return nil, fmt.Errorf("invalid byte value in %s: %d", name, v)
		}
		b[i] = byte(v)
	}
	return b, nil
}

// createTestCertificate creates a test certificate.
func createTestCertificate(template *x509.Certificate, signer *x509.Certificate, pubKey crypto.PublicKey, privKey crypto.PrivateKey) ([]byte, *x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, signer, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, cert, nil
}

// computeSKI calculates the Subject Key Identifier for a public key.
func computeSKI(pubKey crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

// generateDeviceID creates a new random device ID.
func generateDeviceID() (*dpb.DeviceId, *ate.DeviceIDBytes, error) {
	devIdProto := &dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
			ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
			DeviceIdentificationNumber: mrand.Uint64(),
		},
		SkuSpecific: make([]byte, dtd.DeviceIdSkuSpecificLenInBytes),
	}
	if _, err := rand.Read(devIdProto.SkuSpecific); err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKU specific data: %w", err)
	}
	dBytes, err := devid.DeviceIDToRawBytes(devIdProto)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert device ID to raw bytes: %v", err)
	}
	var deviceID ate.DeviceIDBytes
	copy(deviceID.Raw[:], dBytes)
	return devIdProto, &deviceID, nil
}

// generateDeviceKeys generates the device keys based on the certificate chain leaf.
func generateDeviceKeys(privKeys map[string]*ecdsa.PrivateKey, certChainDiceLeaf string) error {
	var devKeys []string
	if certChainDiceLeaf == "CDI_0" {
		devKeys = []string{"CDI_0"}
	} else if certChainDiceLeaf == "CDI_1" {
		devKeys = []string{"CDI_0", "CDI_1"}
	}

	for _, label := range devKeys {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate private key %q: %w", label, err)
		}
		privKeys[label] = key
	}
	return nil
}

// NewDut creates and initializes a new emulated DUT.
func NewDut(opts skumgr.Options, skuName string) (*Dut, error) {
	_, deviceID, err := generateDeviceID()
	if err != nil {
		return nil, err
	}

	skuMgr := skumgr.NewManager(opts)
	skuConfig, err := skuMgr.GetSkuConfig(skuName)
	if err != nil {
		return nil, fmt.Errorf("failed to get SKU config for SKU %q: %v", skuName, err)
	}

	certChainDiceLeaf, err := skuConfig.GetUnsafeAttribute(skucfg.AttrNameCertChainDiceLeaf)
	if err != nil {
		return nil, fmt.Errorf("unable to get cert chain dice leaf: %v", err)
	}

	return &Dut{
		skuMgr:              skuMgr,
		skuName:             skuName,
		skuConfig:           skuConfig,
		DeviceID:            deviceID,
		waferAuthSecret:     []byte{},
		testUnlockToken:     []byte{},
		testExitToken:       []byte{},
		rmaTokenHash:        []byte{},
		wrappedRmaTokenSeed: []byte{},
		caSubjectKeyIds:     [][]byte{},
		certChainDiceLeaf:   certChainDiceLeaf,
	}, nil
}

func (d *Dut) ExpectedExtCerts() (int, error) {
	if _, err := d.skuConfig.GetUnsafeAttribute("SigningKey/Ext/v0"); err == nil {
		var numDiceCerts int
		switch d.certChainDiceLeaf {
		case "UDS":
			numDiceCerts = 1
		case "CDI_0":
			numDiceCerts = 2
		case "CDI_1":
			numDiceCerts = 3
		}
		if d.skuConfig.CertCountX509 < numDiceCerts {
			return 0, fmt.Errorf("expected at least %d X.509 certificates, got %d", numDiceCerts, d.skuConfig.CertCountX509)
		}
		return d.skuConfig.CertCountX509 - numDiceCerts, nil
	}
	return 0, nil
}

func (d *Dut) BuildTbsCerts() error {
	// Generate TBS certificates for the DUT. This requires accessing the HSM.
	certLabels := []string{"UDS"}

	numExtCerts, err := d.ExpectedExtCerts()
	if err != nil {
		return fmt.Errorf("failed to get expected number of EXT certificates: %v", err)
	}

	for i := 0; i < numExtCerts; i++ {
		certLabels = append(certLabels, fmt.Sprintf("EXT_%d", i))
	}

	tbsCerts, privKeys, err := tbsgen.BuildTestTBSCerts(d.skuMgr, d.skuName, certLabels)
	if err != nil {
		return fmt.Errorf("failed to generate TBS certificates for SKU %q: %v", d.skuName, err)
	}

	if err := generateDeviceKeys(privKeys, d.certChainDiceLeaf); err != nil {
		return fmt.Errorf("failed to generate device keys: %v", err)
	}

	d.tbsCerts = tbsCerts
	d.privKeys = privKeys
	return nil
}

// GenerateCpDeviceIDJson generates a device ID and returns it as a JSON payload.
func (d *Dut) GenerateCpDeviceIDJson() ([]byte, error) {
	time.Sleep(GenerateCpDeviceIDJsonDelay)
	// The CP device ID is the hardware origin part of the full device ID,
	// which is the first 16 bytes.
	hwOriginBytes := d.DeviceID.Raw[0:cpDeviceIDLenInBytes]
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
	hwOrigin := d.DeviceID.Raw[0:cpDeviceIDLenInBytes]
	// The ATE DLL API requires a diversifier of 48 bytes. We emulate this by creating
	// a 48 byte slice and appending the hardware ID to it. The first 3 bytes are
	// "was" and the rest are the hardware ID.
	dID := make([]byte, wasDiversifierLen)
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

	var err error
	d.waferAuthSecret, err = parseWaferAuthSecret(tokens.WaferAuthSecret, "wafer_auth_secret")
	if err != nil {
		return err
	}
	d.testUnlockToken, err = parseTokenHash(tokens.TestUnlockTokenHash, "test_unlock_token_hash")
	if err != nil {
		return err
	}
	d.testExitToken, err = parseTokenHash(tokens.TestExitTokenHash, "test_exit_token_hash")
	if err != nil {
		return err
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

	var err error
	d.rmaTokenHash, err = parseTokenHash(token.Hash, "rma_token_hash")
	if err != nil {
		return err
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

	diceKey, err := parseAuthKeyID(keys.DiceAuthKeyKeyId, "dice_auth_key_key_id")
	if err != nil {
		return err
	}
	extKey, err := parseAuthKeyID(keys.ExtAuthKeyKeyId, "ext_auth_key_key_id")
	if err != nil {
		return err
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

	var tbsBytesToSign bytes.Buffer
	var x509TbsCerts []ate.EndorseCertRequest
	for label, tbs := range d.tbsCerts {
		x509TbsCerts = append(x509TbsCerts, ate.EndorseCertRequest{
			KeyLabel: label,
			Tbs:      tbs,
		})
		tbsBytesToSign.Write(tbs)
	}

	// Create a signature over the TBS certs.
	var signature ate.EndorseCertSignature
	if len(d.waferAuthSecret) != waferAuthSecretLenInBytes {
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


// GenerateDummyCwtCerts generates dummy CWT certificates.
// The Cert payload is a random 256 bytes.
func (d * Dut) GenerateDummyCwtCerts() ([]ate.EndorseCertResponse, error) {
	certs := make([]ate.EndorseCertResponse, d.skuConfig.CertCountCWT)
	for i := 0; i < d.skuConfig.CertCountCWT; i++ {
		randBytes := make([]byte, 256)
		if _, err := rand.Read(randBytes); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		log.Printf("Generated dummy CWT certificate %d", i)
		certs[i] = ate.EndorseCertResponse{
			KeyLabel: fmt.Sprintf("CWT_%d", i),
			Cert:     randBytes,
		}
	}
	return certs, nil
}

// GeneratePersoTlv builds a personalization TLV blob containing endorsed 
// certificates.
func (d *Dut) GeneratePersoTlv() ([]byte, uint32, error) {
	time.Sleep(GeneratePersoBlobDelay)

	cwtCerts, err := d.GenerateDummyCwtCerts()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate dummy CWT certificates: %w", err)
	}

	persoBlob := &ate.PersoBlob{
		X509Certs: []ate.EndorseCertResponse{},
		CwtCerts:  cwtCerts,
	}

	// Find endorsed UDS certificate.
	var udsCert *x509.Certificate
	for _, cert := range d.endorsedCerts {
		if cert.KeyLabel == "UDS" {
			var err error
			udsCert, err = x509.ParseCertificate(cert.Cert)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse UDS certificate: %w", err)
			}
		}
		persoBlob.X509Certs = append(persoBlob.X509Certs, cert)
	}
	if udsCert == nil {
		return nil, 0, fmt.Errorf("UDS certificate not found in endorsed certs")
	}

	if d.certChainDiceLeaf == "UDS" {
		blobBytes, err := ate.BuildPersoBlob(persoBlob)
		if err != nil {
			return nil, 0, err
		}
		return blobBytes, uint32(len(persoBlob.X509Certs)), nil
	}

	// Create CDI_0 certificate endorsed by UDS.
	cdi0Template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"CDI_0 Test Certificate"},
			CommonName:   "CDI_0",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Issuer:                udsCert.Subject,
		AuthorityKeyId:        udsCert.SubjectKeyId,
	}
	cdi0Ski, err := computeSKI(&d.privKeys["CDI_0"].PublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute CDI_0 SKI: %w", err)
	}
	cdi0Template.SubjectKeyId = cdi0Ski
	cdi0CertBytes, cdi0Cert, err := createTestCertificate(cdi0Template, udsCert, &d.privKeys["CDI_0"].PublicKey, d.privKeys["UDS"])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create CDI_0 certificate: %w", err)
	}

	persoBlob.X509Certs = append(persoBlob.X509Certs, ate.EndorseCertResponse{
		KeyLabel: "CDI_0",
		Cert:     cdi0CertBytes,
	})

	// If the certificate chain is CDI_0, we don't need to create CDI_1.
	if d.certChainDiceLeaf == "CDI_0" {
		blobBytes, err := ate.BuildPersoBlob(persoBlob)
		if err != nil {
			return nil, 0, err
		}
		return blobBytes, uint32(len(persoBlob.X509Certs)), nil
	}

	// Create a CDI_1 certificate endorsed by CDI_0.
	cdi1Template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"CDI_1 Test Certificate"},
			CommonName:   "CDI_1",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		Issuer:                cdi0Cert.Subject,
		AuthorityKeyId:        cdi0Cert.SubjectKeyId,
	}
	cdi1Ski, err := computeSKI(&d.privKeys["CDI_1"].PublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute CDI_1 SKI: %w", err)
	}
	cdi1Template.SubjectKeyId = cdi1Ski
	cdi1CertBytes, _, err := createTestCertificate(cdi1Template, cdi0Cert, &d.privKeys["CDI_1"].PublicKey, d.privKeys["CDI_0"])
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create CDI_1 certificate: %w", err)
	}

	persoBlob.X509Certs = append(persoBlob.X509Certs, ate.EndorseCertResponse{
		KeyLabel: "CDI_1",
		Cert:     cdi1CertBytes,
	})

	blobBytes, err := ate.BuildPersoBlob(persoBlob)
	if err != nil {
		return nil, 0, err
	}

	numObjs := len(persoBlob.X509Certs) + len(persoBlob.CwtCerts)
	return blobBytes, uint32(numObjs), nil
}
