// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package se

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"testing"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"golang.org/x/crypto/sha3"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	ts "github.com/lowRISC/opentitan-provisioning/src/pk11/test_support"
)

const (
	diceTBSPath    = "src/spm/services/testdata/tbs.der"
	diceCAKeyPath  = "src/spm/services/testdata/sk.pkcs8.der"
	diceCACertPath = "src/spm/services/testdata/dice_ca.pem"
)

// readFile reads a file from the runfiles directory.
func readFile(t *testing.T, filename string) []byte {
	t.Helper()
	filename, err := bazel.Runfile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("unable to load file: %q, error: %v", filename, err)
	}
	return data
}

// Creates a new HSM for a test by reaching into the tests's SoftHSM token.
func MakeHSM(t *testing.T) (*HSM, []byte, []byte) {
	t.Helper()
	s := ts.GetSession(t)
	ts.Check(t, s.Login(pk11.NormalUser, ts.UserPin))

	// Initialize HSM with KHsks.
	hs := sha256.Sum256([]byte("high security seed"))
	hsSeed := hs[:]
	hsks, err := s.ImportGenericSecret(hsSeed, &pk11.KeyOptions{Extractable: false})
	ts.Check(t, err)
	hsksUID, err := hsks.UID()
	ts.Check(t, err)

	// Initialize HSM with KLsks.
	ls := sha256.Sum256([]byte("low security seed"))
	lsSeed := ls[:]
	lsks, err := s.ImportGenericSecret(lsSeed, &pk11.KeyOptions{Extractable: false})
	ts.Check(t, err)
	lsksUID, err := lsks.UID()
	ts.Check(t, err)

	// Initialize HSM with TokenWrappingKey.
	twrap, err := s.GenerateRSA(3072, 0x010001, &pk11.KeyOptions{
		Extractable: true,
		Token:       true,
		Wrapping:    true,
		Encryption:  true,
	})
	ts.Check(t, err)

	err = twrap.PrivateKey.SetLabel("TokenWrappingKey")
	ts.Check(t, err)
	twpPrivUID, err := twrap.PrivateKey.UID()
	ts.Check(t, err)

	err = twrap.PublicKey.SetLabel("TokenWrappingKey")
	ts.Check(t, err)
	twpPubUID, err := twrap.PublicKey.UID()
	ts.Check(t, err)

	// Initialize session queue.
	numSessions := 1
	sessions := newSessionQueue(numSessions)
	err = sessions.insert(s)
	ts.Check(t, err)

	return &HSM{
			SymmetricKeys: map[string][]byte{
				"HighSecKdfSeed": hsksUID,
				"LowSecKdfSeed":  lsksUID,
			},
			PublicKeys: map[string][]byte{
				"TokenWrappingKey": twpPubUID,
			},
			PrivateKeys: map[string][]byte{
				"TokenWrappingKey": twpPrivUID,
			},
			sessions: sessions,
		},
		hsSeed,
		lsSeed
}

func TestGenerateSymmKeys(t *testing.T) {
	hsm, hsSeed, lsSeed := MakeHSM(t)

	// test unlock token
	testUnlockTokenParams := TokenParams{
		SeedLabel:   "LowSecKdfSeed",
		Type:        TokenTypeSecurityLo,
		Op:          TokenOpRaw,
		SizeInBits:  128,
		Sku:         "test sku",
		Diversifier: "test_unlock",
		Wrap:        WrappingMechanismNone,
	}
	// test exit token
	testExitTokenParams := TokenParams{
		SeedLabel:   "LowSecKdfSeed",
		Type:        TokenTypeSecurityLo,
		Op:          TokenOpRaw,
		SizeInBits:  128,
		Sku:         "test sku",
		Diversifier: "test_exit",
		Wrap:        WrappingMechanismNone,
	}
	// wafer authentication token
	wasParams := TokenParams{
		SeedLabel:   "HighSecKdfSeed",
		Type:        TokenTypeSecurityHi,
		Op:          TokenOpRaw,
		SizeInBits:  256,
		Sku:         "test sku",
		Diversifier: "was",
		Wrap:        WrappingMechanismNone,
	}
	params := []*TokenParams{
		&testUnlockTokenParams,
		&testExitTokenParams,
		&wasParams,
	}

	// Generate the actual tokens (using the HSM).
	res, err := hsm.GenerateTokens(params)
	ts.Check(t, err)
	tokens := make([][]byte, len(res))
	for i, r := range res {
		tokens[i] = r.Token
	}

	// Check actual tokens match those generated using the go crypto package.
	for i, p := range params {
		// Generate expected token.
		var seed []byte
		if p.Type == TokenTypeSecurityHi {
			seed = hsSeed
		} else {
			seed = lsSeed
		}
		h2 := hmac.New(sha256.New, seed)
		h2.Write([]byte(p.Sku + p.Diversifier))
		expected_token := h2.Sum(nil)[:p.SizeInBits/8]

		if p.Op == TokenOpHashedOtLcToken {
			hasher := sha3.NewCShake128([]byte(""), []byte("LC_CTRL"))
			hasher.Write(expected_token)
			hasher.Read(expected_token)
		}

		// Check the actual and expected tokens are equal.
		log.Printf("Actual   Token: %q", hex.EncodeToString(tokens[i]))
		log.Printf("Expected Token: %q", hex.EncodeToString(expected_token))
		if !bytes.Equal(tokens[i], expected_token) {
			t.Fatal("token generation failed")
		}
	}
}

func TestGenerateSymmKeysWrap(t *testing.T) {
	hsm, _, _ := MakeHSM(t)

	// RMA token
	rmaParams := TokenParams{
		Type:         TokenTypeKeyGen,
		Op:           TokenOpHashedOtLcToken,
		SizeInBits:   128,
		Sku:          "test sku",
		Diversifier:  "rma: device_id",
		Wrap:         WrappingMechanismRSAPCKS,
		WrapKeyLabel: "TokenWrappingKey",
	}
	params := []*TokenParams{
		&rmaParams,
	}

	// Generate the actual tokens (using the HSM).
	res, err := hsm.GenerateTokens(params)
	ts.Check(t, err)
	if len(res) != 1 {
		t.Fatal("expected 1 token, got", len(res))
	}
	r := res[0]

	// Unwrap the token using the HSM and check that the unwrapped token matches
	// the expected one.
	expected_token := func() []byte {
		s, release := hsm.sessions.getHandle()
		defer release()

		wk, _ := hsm.PrivateKeys["TokenWrappingKey"]
		pk, err := s.FindPrivateKey(wk)
		ts.Check(t, err)

		seed, err := s.UnwrapGenSecret(r.WrappedKey, pk, pk11.GenSecretWrapMechanismRsaPcks, &pk11.KeyOptions{Extractable: true})
		ts.Check(t, err)

		tBytes, err := seed.SignHMAC256([]byte(rmaParams.Sku + rmaParams.Diversifier))
		ts.Check(t, err)
		tBytes = tBytes[:rmaParams.SizeInBits/8]

		hasher := sha3.NewCShake128([]byte(""), []byte("LC_CTRL"))
		hasher.Write(tBytes)
		hasher.Read(tBytes)
		return tBytes
	}()

	log.Printf("Actual   Token: %q", hex.EncodeToString(r.Token))
	log.Printf("Expected Token: %q", hex.EncodeToString(expected_token))
	if !bytes.Equal(r.Token, expected_token) {
		t.Fatal("generate token failed")
	}
}

// MintECDSAKeys generates a P256 ECDSA key pair to be used by various tests
// below as the keys to a Certificate Authority (CA) or HSM identity.
// It requires an initialized `hsm` instance.
func MintECDSAKeys(t *testing.T, hsm *HSM) (pk11.KeyPair, error) {
	session, release := hsm.sessions.getHandle()
	defer release()
	return session.GenerateECDSA(elliptic.P256(), &pk11.KeyOptions{Extractable: true})
}

func TestEndorseCert(t *testing.T) {
	log.Printf("TestEndorseCert")
	hsm, _, _ := MakeHSM(t)

	const kcaPrivName = "kca_priv"

	// The following nested function is required to avoid deadlocks when calling
	// `hsm.sessions.getHandle()` in the `EndorseCert` function.
	importCAKey := func() {
		privateKeyDer := readFile(t, diceCAKeyPath)
		privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDer)
		ts.Check(t, err)

		// Import the CA key into the HSM.
		session, release := hsm.sessions.getHandle()
		defer release()

		// Cast the private key to an ECDSA private key to make sure the
		// `ImportKey` function imports the key as an ECDSA key.
		privateKey = privateKey.(*ecdsa.PrivateKey)
		ca, err := session.ImportKey(privateKey, &pk11.KeyOptions{
			Extractable: true,
			Token:       true,
		})
		ts.Check(t, err)
		err = ca.SetLabel(kcaPrivName)
		ts.Check(t, err)
	}

	importCAKey()
	caCertPEM := readFile(t, diceCACertPath)
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	ts.Check(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	log.Printf("Reading TBS")
	tbs := readFile(t, diceTBSPath)

	log.Printf("Endorsing cert")
	certDER, err := hsm.EndorseCert(tbs, EndorseCertParams{
		KeyLabel:           kcaPrivName,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})
	ts.Check(t, err)

	cert, err := x509.ParseCertificate(certDER)
	ts.Check(t, err)

	// DICE extensions marked as critical end up in this list. We explicitly
	// clear the list to get x509.Verify to pass.
	cert.UnhandledCriticalExtensions = nil

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	ts.Check(t, err)
}

func TestEndorseData(t *testing.T) {
	log.Printf("TestEndorseData")
	hsm, _, _ := MakeHSM(t)

	// Mint ECDSA keys on HSM.
	identityKeyPair, err := MintECDSAKeys(t, hsm)
	ts.Check(t, err)

	_, release := hsm.sessions.getHandle()
	// Add labels to key objects in the HSM.
	const kIdPrivName = "kid_priv"
	const kIdPubName = "kid_pub"
	err = identityKeyPair.PrivateKey.SetLabel(kIdPrivName)
	ts.Check(t, err)
	err = identityKeyPair.PublicKey.SetLabel(kIdPubName)
	ts.Check(t, err)
	// Export public key from HSM.
	idPublicKeyExported, err := identityKeyPair.PublicKey.ExportKey()
	ts.Check(t, err)
	idPublicKey := idPublicKeyExported.(*ecdsa.PublicKey)
	release()

	log.Printf("Reading data")
	data := readFile(t, diceTBSPath)

	// Perform data signature operation.
	log.Printf("Endorsing data")
	asn1PubKey, asn1Sig, err := hsm.EndorseData(data, EndorseCertParams{
		KeyLabel:           kIdPrivName,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})
	ts.Check(t, err)

	// Check public keys match.
	var pubKey struct{ X, Y *big.Int }
	_, err = asn1.Unmarshal(asn1PubKey, &pubKey)
	if pubKey.X.Cmp(idPublicKey.X) != 0 {
		t.Fatal("pubkey (X) exported does not match one in HSM")
	}
	if pubKey.Y.Cmp(idPublicKey.Y) != 0 {
		t.Fatal("pubkey (Y) exported does not match one in HSM")
	}

	// Verify signatures.
	log.Printf("Verifying data signature")
	dataHash := sha256.Sum256(data)
	var sig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(asn1Sig, &sig)
	verfied := ecdsa.Verify(idPublicKey, dataHash[:], sig.R, sig.S)
	if !verfied {
		t.Errorf("signature failed to verify")
	}
}
