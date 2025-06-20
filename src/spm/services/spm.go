// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package spm implements the gRPC Spm server interface.
package spm

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/ate"
	"github.com/lowRISC/opentitan-provisioning/src/proto/validators"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skumgr"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service/session_token"
	"github.com/lowRISC/opentitan-provisioning/src/utils"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
)

// Options contain configuration options for the SPM service.
type Options struct {
	// HSMSOLibPath contains the path to the PCKS#11 interface used to connect
	// to the HSM.
	HSMSOLibPath string

	// SPMAuthConfigFile contains the path to the SPM authentication
	// configuration file.
	SPMAuthConfigFile string

	// SPMConfigDir contains the path to the SPM configuration directory. All
	// configuration files must be relative to this path.
	SPMConfigDir string

	// File contains the full file path of the HSM's password
	HsmPWFile string
}

// server is the server object.
type server struct {
	// configDir points to the directory holding all SKU configuration files
	// and assets.
	configDir string

	// hsmSOLibPath points to the HSM dynamic library file path.
	hsmSOLibPath string

	// hsmPasswordFile holds the full file path of the HSM's password
	hsmPasswordFile string

	// authCfg contains the configuration of the authentication token
	authCfg *skucfg.Auth

	// skuManager manages SKU configurations and assets.
	skuManager *skumgr.Manager
}

const (
	SubjectKeySize int  = 10
	TokenSize      int  = 16
	BigEndian      bool = true
	LittleEndian   bool = false
)

func generateSessionToken(n int) (string, error) {
	token, err := session_token.GetInstance()
	if err != nil {
		return "", err
	}
	return token.Generate(n)
}

// NewSpmServer returns an implementation of the SPM gRPC server.
func NewSpmServer(opts Options) (pbs.SpmServiceServer, error) {
	if _, err := os.Stat(opts.SPMConfigDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("config directory does not exist: %q, error: %v", opts.SPMConfigDir, err)
	}

	var config skucfg.Auth
	err := utils.LoadConfig(opts.SPMConfigDir, opts.SPMAuthConfigFile, &config)
	if err != nil {
		return nil, fmt.Errorf("could not load sku auth config: %v", err)
	}

	session_token.NewSessionTokenInstance()

	skuManager := skumgr.NewManager(skumgr.Options{
		ConfigDir:       opts.SPMConfigDir,
		HSMSOLibPath:    opts.HSMSOLibPath,
		HsmPasswordFile: opts.HsmPWFile,
	})

	return &server{
		configDir:       opts.SPMConfigDir,
		hsmSOLibPath:    opts.HSMSOLibPath,
		hsmPasswordFile: opts.HsmPWFile,
		authCfg: &skucfg.Auth{
			SkuAuthCfgList: config.SkuAuthCfgList,
		},
		skuManager: skuManager,
	}, nil
}

func (s *server) initSku(sku string) (string, error) {
	token, err := generateSessionToken(TokenSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate session token: %v", err)
	}
	_, err = s.skuManager.LoadSku(sku)
	if err != nil {
		return "", fmt.Errorf("failed to initialize sku: %v", err)
	}
	return token, nil
}

// findSkuAuth returns an empty sku auth config, if nor sku or a family sku can be found
// in the map config, otherwise the relavent sku auth config will be return.
func (s *server) findSkuAuth(sku string) (skucfg.SkuAuth, bool) {
	auth := skucfg.SkuAuth{}
	if auth, found := s.authCfg.SkuAuthCfgList[sku]; found {
		return auth, true
	}

	// Iterate over the skus in the map and search for the family sku
	for familySku := range s.authCfg.SkuAuthCfgList {
		if strings.HasPrefix(sku, familySku) {
			auth = s.authCfg.SkuAuthCfgList[familySku]
			return auth, true
		}
	}

	return skucfg.SkuAuth{}, false
}

func (s *server) InitSession(ctx context.Context, request *pbp.InitSessionRequest) (*pbp.InitSessionResponse, error) {
	log.Printf("SPM.InitSessionRequest - Sku:%q", request.Sku)

	// search sku & products
	var auth skucfg.SkuAuth
	var found bool
	if s.authCfg != nil {
		if auth, found = s.findSkuAuth(request.Sku); !found {
			return nil, status.Errorf(codes.Internal, "unknown sku: %q", request.Sku)
		}
		err := utils.CompareHashAndPassword(auth.SkuAuth, request.SkuAuth)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "incorrect sku authentication %q", request.SkuAuth)
		}
	} else {
		return nil, status.Errorf(codes.Internal, "authentication config pointer is nil")
	}

	token, err := s.initSku(request.Sku)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to initialize sku: %v", err)
	}

	return &pbp.InitSessionResponse{
		SkuSessionToken: token,
		AuthMethods:     auth.Methods,
	}, nil
}

func (s *server) DeriveTokens(ctx context.Context, request *pbp.DeriveTokensRequest) (*pbp.DeriveTokensResponse, error) {
	sku, ok := s.skuManager.GetSku(request.Sku)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	sLabelHi, err := sku.Config.GetAttribute(skucfg.AttrNameSeedSecHi)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not fetch seed label %q: %v", skucfg.AttrNameSeedSecHi, err)
	}

	sLabelLo, err := sku.Config.GetAttribute(skucfg.AttrNameSeedSecLo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not fetch seed label %q: %v", skucfg.AttrNameSeedSecLo, err)
	}

	// Build parameter list for all keygens requested.
	var keygenParams []*se.TokenParams
	for _, p := range request.Params {
		params := new(se.TokenParams)

		// Retrieve seed configuration.
		switch p.Seed {
		case pbp.TokenSeed_TOKEN_SEED_HIGH_SECURITY:
			params.Type = se.TokenTypeSecurityHi
			params.SeedLabel = sLabelHi
		case pbp.TokenSeed_TOKEN_SEED_LOW_SECURITY:
			params.Type = se.TokenTypeSecurityLo
			params.SeedLabel = sLabelLo
		case pbp.TokenSeed_TOKEN_SEED_KEYGEN:
			params.Type = se.TokenTypeKeyGen
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid key seed requested: %d", p.Seed)
		}

		if p.WrapSeed {
			wmech, err := sku.Config.GetAttribute(skucfg.AttrNameWrappingMechanism)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "could not get wrapping method: %s", err)
			}
			switch wmech {
			case skucfg.WrappingMechanismRSAOAEP:
				params.Wrap = se.WrappingMechanismRSAOAEP
			case skucfg.WrappingMechanismRSAPKCS1:
				params.Wrap = se.WrappingMechanismRSAPCKS
			default:
				return nil, status.Errorf(codes.Internal, "invalid wrapping method: %s", wmech)
			}

			wkl, err := sku.Config.GetAttribute(skucfg.AttrNameWrappingKeyLabel)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "could not get wrapping key label: %s", err)
			}
			params.WrapKeyLabel = wkl
		} else {
			params.Wrap = se.WrappingMechanismNone
		}

		// Retrieve key size.
		if p.Size == pbp.TokenSize_TOKEN_SIZE_128_BITS {
			params.SizeInBits = 128
		} else if p.Size == pbp.TokenSize_TOKEN_SIZE_256_BITS {
			params.SizeInBits = 256
		} else {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid key size requested: %d", p.Size)
		}

		// Retrieve key type.
		if p.Type == pbp.TokenType_TOKEN_TYPE_RAW {
			params.Op = se.TokenOpRaw
		} else if p.Type == pbp.TokenType_TOKEN_TYPE_HASHED_OT_LC_TOKEN {
			params.Op = se.TokenOpHashedOtLcToken
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "invalid key type requested: %d", p.Type)
		}

		params.Sku = request.Sku
		params.Diversifier = p.Diversifier

		keygenParams = append(keygenParams, params)
	}

	// Generate the symmetric keys.
	res, err := sku.SeHandle.GenerateTokens(keygenParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate symmetric key: %s", err)
	}

	tokens := make([]*pbp.Token, len(res))
	for i, r := range res {
		tokens[i] = &pbp.Token{
			Token:       r.Token,
			WrappedSeed: r.WrappedKey,
		}
	}

	return &pbp.DeriveTokensResponse{
		Tokens: tokens,
	}, nil
}

// ecdsaSignatureAlgorithmFromHashType returns the x509.SignatureAlgorithm
// corresponding to the given pbcommon.HashType.
func ecdsaSignatureAlgorithmFromHashType(h pbcommon.HashType) x509.SignatureAlgorithm {
	switch h {
	case pbcommon.HashType_HASH_TYPE_SHA256:
		return x509.ECDSAWithSHA256
	case pbcommon.HashType_HASH_TYPE_SHA384:
		return x509.ECDSAWithSHA384
	case pbcommon.HashType_HASH_TYPE_SHA512:
		return x509.ECDSAWithSHA512
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// GetCaSubjectKeys retrieves the CA certificate(s) subject keys for a SKU.
func (s *server) GetCaSubjectKeys(ctx context.Context, request *pbp.GetCaSubjectKeysRequest) (*pbp.GetCaSubjectKeysResponse, error) {
	sku, ok := s.skuManager.GetSku(request.Sku)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	// Extract the subject key from each certificate.
	var subjectKeys [][]byte
	for _, label := range request.CertLabels {
		var kl string
		if label == "UDS" {
			kl = "SigningKey/Dice/v0"
		} else {
			kl = "SigningKey/Ext/v0"
		}

		cert, ok := sku.Certs[kl]
		if !ok {
			emptySK := make([]byte, SubjectKeySize)
			log.Printf("SPM.GetCaSubjectKeys - unable to find cert %q in SKU configuration", kl)
			subjectKeys = append(subjectKeys, emptySK)
			continue
		}

		subjectKeys = append(subjectKeys, cert.SubjectKeyId)
	}

	return &pbp.GetCaSubjectKeysResponse{
		KeyIds: subjectKeys,
	}, nil
}

// GetStoredTokens retrieves a provisioned token from the SPM's HSM.
func (s *server) GetStoredTokens(ctx context.Context, request *pbp.GetStoredTokensRequest) (*pbp.GetStoredTokensResponse, error) {
	return nil, status.Errorf(codes.Internal, "SPM.GetStoredTokens - unimplemented")
}

func (s *server) EndorseCerts(ctx context.Context, request *pbp.EndorseCertsRequest) (*pbp.EndorseCertsResponse, error) {
	log.Printf("SPM.EndorseCertsRequest - Sku:%q", request.Sku)

	sku, ok := s.skuManager.GetSku(request.Sku)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	wasData := []byte{}
	for _, cert := range request.Bundles {
		if cert.Tbs != nil {
			wasData = append(wasData, cert.Tbs...)
		}
	}
	if len(wasData) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "no data to endorse")
	}

	wasLabel, err := sku.Config.GetAttribute(skucfg.AttrNameWASKeyLabel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not get WAS key label: %s", err)
	}

	// The WASDisable attribute will be removed in a future version of the spm.
	wasDisable, err := sku.Config.GetAttribute(skucfg.AttrNameWASDisable)
	if err != nil {
		wasDisable = "false"
	}

	err = sku.SeHandle.VerifyWASSignature(se.VerifyWASParams{
		Signature:   request.Signature,
		Data:        wasData,
		Diversifier: request.Diversifier,
		Sku:         request.Sku,
		Seed:        wasLabel,
		LogOnly:     wasDisable == "true",
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not verify WAS signature: %s", err)
	}

	rootCert, ok := sku.Certs["RootCA"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to find RootCA cert in SKU configuration")
	}

	var certs []*pbp.CertBundle
	for _, bundle := range request.Bundles {
		if bundle.KeyParams == nil {
			return nil, status.Errorf(codes.InvalidArgument, "missing key params")
		}
		if bundle.Tbs == nil {
			return nil, status.Errorf(codes.InvalidArgument, "missing tbs data")
		}

		var kl string
		if bundle.KeyParams.KeyLabel == "UDS" {
			kl = "SigningKey/Dice/v0"
		} else {
			kl = "SigningKey/Ext/v0"
		}

		keyLabel, err := sku.Config.GetUnsafeAttribute(kl)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to find key label %q in SKU configuration: %v", kl, err)
		}

		caCert, ok := sku.Certs[kl]
		if !ok {
			return nil, status.Errorf(codes.Internal, "unable to find cert %q in SKU configuration", bundle.KeyParams.KeyLabel)
		}

		switch key := bundle.KeyParams.Key.(type) {
		case *pbc.SigningKeyParams_EcdsaParams:
			params := se.EndorseCertParams{
				KeyLabel:           keyLabel,
				SignatureAlgorithm: ecdsaSignatureAlgorithmFromHashType(key.EcdsaParams.HashType),
				Intermediates: []*x509.Certificate{
					caCert,
				},
				Roots: []*x509.Certificate{
					rootCert,
				},
			}
			cert, err := sku.SeHandle.EndorseCert(bundle.Tbs, params)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "could not endorse cert: %v", err)
			}
			certs = append(certs, &pbp.CertBundle{
				KeyLabel: bundle.KeyParams.KeyLabel,
				Cert: &pbc.Certificate{
					Blob: cert,
				},
			})
		default:
			return nil, status.Errorf(codes.Unimplemented, "unsupported key format")
		}
	}
	return &pbp.EndorseCertsResponse{
		Certs: certs,
	}, nil
}

func (s *server) EndorseData(ctx context.Context, request *pbs.EndorseDataRequest) (*pbs.EndorseDataResponse, error) {
	log.Printf("SPM.EndorseDataRequest - Sku:%q", request.Sku)
	sku, ok := s.skuManager.GetSku(request.Sku)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	// Retrieve signing key label.
	keyLabel, err := sku.Config.GetUnsafeAttribute(request.KeyParams.KeyLabel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to find key label %q in SKU configuration: %v", request.KeyParams.KeyLabel, err)
	}

	// Sign data payload with the endorsement key.
	var asn1Pubkey, asn1Sig []byte
	switch key := request.KeyParams.Key.(type) {
	case *pbc.SigningKeyParams_EcdsaParams:
		params := se.EndorseCertParams{
			KeyLabel:           keyLabel,
			SignatureAlgorithm: ecdsaSignatureAlgorithmFromHashType(key.EcdsaParams.HashType),
		}
		asn1Pubkey, asn1Sig, err = sku.SeHandle.EndorseData(request.Data, params)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not endorse data payload: %v", err)
		}
		pub, err := x509.ParsePKIXPublicKey(asn1Pubkey)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not parse public key: %v", err)
		}
		ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, status.Errorf(codes.Internal, "public key is not an ECDSA key")
		}

		dataHash := sha256.Sum256(request.Data)
		var sig struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(asn1Sig, &sig)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not unmarshal signature: %v", err)
		}

		// Verify the signature.
		verified := ecdsa.Verify(ecdsaPubKey, dataHash[:], sig.R, sig.S)
		if !verified {
			return nil, status.Errorf(codes.Internal, "could not verify signature")
		}
	default:
		return nil, status.Errorf(codes.Unimplemented, "unsupported key format")
	}

	return &pbs.EndorseDataResponse{
		Pubkey:    asn1Pubkey,
		Signature: asn1Sig,
	}, nil
}

func (s *server) VerifyDeviceData(ctx context.Context, request *pbs.VerifyDeviceDataRequest) (*pbs.VerifyDeviceDataResponse, error) {
	log.Printf("SPM.VerifyDeviceDataRequest - Sku:%q", request.DeviceData.Sku)
	sku, ok := s.skuManager.GetSku(request.DeviceData.Sku)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.DeviceData.Sku)
	}

	// Unpack the perso blob.
	persoBlob, err := ate.UnpackPersoBlob(request.DeviceData.PersoTlvData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unpack perso blob: %v", err)
	}

	// Validate the device ID.
	if err := validators.ValidateDeviceId(request.DeviceData.DeviceId); err != nil {
		return nil, status.Errorf(codes.Internal, "device ID is invalid: %v", err)
	}

	rootCert, ok := sku.Certs["RootCA"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to find RootCA cert in SKU configuration")
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	udsICA, ok := sku.Certs["SigningKey/Dice/v0"]
	if !ok {
		return nil, status.Errorf(codes.Internal, "unable to find UDS ICA cert in SKU configuration")
	}
	diceIntermediates := x509.NewCertPool()
	diceIntermediates.AddCert(udsICA)

	// EXT ICA is optional. It is used in non-DICE certificate chains.
	extIntermediates := x509.NewCertPool()
	extICA, ok := sku.Certs["SigningKey/Ext/v0"]
	if ok {
		extIntermediates.AddCert(extICA)
	}

	certChainDiceLeaf, err := sku.Config.GetUnsafeAttribute(skucfg.AttrNameCertChainDiceLeaf)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to get cert chain dice leaf: %v", err)
	}

	diceCerts := []*x509.Certificate{}
	extCerts := []*x509.Certificate{}
	extNames := []string{}
	for _, cert := range persoBlob.X509Certs {
		certObj, err := x509.ParseCertificate(cert.Cert)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse certificate: %v", err)
		}
		certObj.UnhandledCriticalExtensions = nil

		// DICE certificate chains are composed based on the certChainDiceLeaf configuration:
		// - If certChainDiceLeaf is "UDS": The chain is Root CA -> UDS ICA -> UDS (leaf)
		// - If certChainDiceLeaf is "CDI_0": The chain is Root CA -> UDS ICA -> UDS -> CDI_0 (leaf)
		// - If certChainDiceLeaf is "CDI_1": The chain is Root CA -> UDS ICA -> UDS -> CDI_0 -> CDI_1 (leaf)
		// The leaf certificate is added to diceCerts for verification, while intermediate
		// certificates are added to the diceIntermediates pool.
		switch cert.KeyLabel {
		case "UDS":
			if certChainDiceLeaf == "UDS" {
				diceCerts = append(diceCerts, certObj)
			} else {
				diceIntermediates.AddCert(certObj)
			}
		case "CDI_0":
			if certChainDiceLeaf == "CDI_0" {
				diceCerts = append(diceCerts, certObj)
			} else if certChainDiceLeaf == "CDI_1" {
				diceIntermediates.AddCert(certObj)
			}
		case "CDI_1":
			if certChainDiceLeaf == "CDI_1" {
				diceCerts = append(diceCerts, certObj)
			} else {
				return nil, status.Errorf(codes.Internal, "CDI_1 certificate chain is not expected for this SKU: %v", err)
			}
		default:
			// If the certificate key label is not one of the DICE certificates,
			// assume it is an EXT leaf certificate.
			// The certificate chain is Root CA -> EXT ICA -> EXT (leaf)
			extCerts = append(extCerts, certObj)
			extNames = append(extNames, cert.KeyLabel)
		}
	}

	// Verify the EXT certificate chains.
	if len(extCerts) > 0 {
		for i, ext := range extCerts {
			_, err := ext.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: extIntermediates,
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%q certificate chain is invalid: %v", extNames[i], err)
			}
		}
	}

	// Verify the DICE certificate chain.
	for _, cert := range diceCerts {
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: diceIntermediates,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%q certificate chain is invalid: %v", cert.Subject.CommonName, err)
		}
	}

	return &pbs.VerifyDeviceDataResponse{}, nil
}
