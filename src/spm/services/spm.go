// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package spm implements the gRPC Spm server interface.
package spm

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service/session_token"
	"github.com/lowRISC/opentitan-provisioning/src/utils"

	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
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

	// skus contains SKU specific configuration only visible to the SPM
	// server.
	skus map[string]*skuState

	// authCfg contains the configuration of the authentication token
	authCfg *skucfg.Auth

	// muSKU is a mutex use to arbitrate SKU initialization access.
	muSKU sync.RWMutex
}

type skuState struct {
	// config contains the SKU configuration data loaded by `InitSession()`.
	config *skucfg.Config

	// certs contains a map of certificates loaded at SKU init configuration.
	// time. They key is the certificate name which can be referenced by SPM
	// clients.
	certs map[string]*x509.Certificate

	// Instance of HSM.
	seHandle se.SE
}

const (
	EKCertSerialNumberSize int  = 10
	TokenSize              int  = 16
	BigEndian              bool = true
	LittleEndian           bool = false
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

	return &server{
		configDir:       opts.SPMConfigDir,
		hsmSOLibPath:    opts.HSMSOLibPath,
		hsmPasswordFile: opts.HsmPWFile,
		skus:            make(map[string]*skuState),
		authCfg: &skucfg.Auth{
			SkuAuthCfgList: config.SkuAuthCfgList,
		},
	}, nil
}

func (s *server) initSku(sku string) (string, error) {
	token, err := generateSessionToken(TokenSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate session token: %v", err)
	}
	err = s.initializeSKU(sku)
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

// DeriveSymmetricKeys generates a symmetric key from a seed and diversification string.
func (s *server) DeriveSymmetricKeys(ctx context.Context, request *pbp.DeriveSymmetricKeysRequest) (*pbp.DeriveSymmetricKeysResponse, error) {
	// Acquire mutex before accessing SKU configuration.
	s.muSKU.RLock()
	defer s.muSKU.RUnlock()
	sku, ok := s.skus[request.Sku]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	sLabelHi, err := sku.config.GetAttribute(skucfg.AttrNameKdfSecHi)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not fetch seed label %q: %v", skucfg.AttrNameKdfSecHi, err)
	}

	sLabelLo, err := sku.config.GetAttribute(skucfg.AttrNameKdfSecLo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not fetch seed label %q: %v", skucfg.AttrNameKdfSecLo, err)
	}

	// Build parameter list for all keygens requested.
	var keygenParams []*se.SymmetricKeygenParams
	for _, p := range request.Params {
		params := new(se.SymmetricKeygenParams)

		// Retrieve seed configuration.
		switch p.Seed {
		case pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_HIGH_SECURITY:
			params.KeyType = se.SymmetricKeyTypeSecurityHi
			params.SeedLabel = sLabelHi
		case pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_LOW_SECURITY:
			params.KeyType = se.SymmetricKeyTypeSecurityLo
			params.SeedLabel = sLabelLo
		case pbp.SymmetricKeySeed_SYMMETRIC_KEY_SEED_KEYGEN:
			params.KeyType = se.SymmetricKeyTypeKeyGen
		default:
			return nil, status.Errorf(codes.InvalidArgument, "invalid key seed requested: %d", p.Seed)
		}

		if p.WrapSeed {
			wmech, err := sku.config.GetAttribute(skucfg.AttrNameWrappingMechanism)
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

			wkl, err := sku.config.GetAttribute(skucfg.AttrNameWrappingKeyLabel)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "could not get wrapping key label: %s", err)
			}
			params.WrapKeyLabel = wkl
		} else {
			params.Wrap = se.WrappingMechanismNone
		}

		// Retrieve key size.
		if p.Size == pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_128_BITS {
			params.SizeInBits = 128
		} else if p.Size == pbp.SymmetricKeySize_SYMMETRIC_KEY_SIZE_256_BITS {
			params.SizeInBits = 256
		} else {
			return nil, status.Errorf(codes.InvalidArgument,
				"invalid key size requested: %d", p.Size)
		}

		// Retrieve key type.
		if p.Type == pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_RAW {
			params.KeyOp = se.SymmetricKeyOpRaw
		} else if p.Type == pbp.SymmetricKeyType_SYMMETRIC_KEY_TYPE_HASHED_OT_LC_TOKEN {
			params.KeyOp = se.SymmetricKeyOpHashedOtLcToken
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "invalid key type requested: %d", p.Type)
		}

		params.Sku = request.Sku
		params.Diversifier = p.Diversifier

		keygenParams = append(keygenParams, params)
	}

	// Generate the symmetric keys.
	res, err := sku.seHandle.GenerateSymmetricKeys(keygenParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate symmetric key: %s", err)
	}

	keys := make([]*pbp.SymmetricKey, len(res))
	for i, r := range res {
		keys[i] = &pbp.SymmetricKey{
			Key:         r.Key,
			WrappedSeed: r.WrappedKey,
		}
	}

	return &pbp.DeriveSymmetricKeysResponse{
		Keys: keys,
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

// GetStoredTokens retrieves a provisioned token from the SPM's HSM.
func (s *server) GetStoredTokens(ctx context.Context, request *pbp.GetStoredTokensRequest) (*pbp.GetStoredTokensResponse, error) {
	return nil, status.Errorf(codes.Internal, "SPM.GetStoredTokens - unimplemented")
}

func (s *server) EndorseCerts(ctx context.Context, request *pbp.EndorseCertsRequest) (*pbp.EndorseCertsResponse, error) {
	log.Printf("SPM.EndorseCertsRequest - Sku:%q", request.Sku)

	s.muSKU.RLock()
	defer s.muSKU.RUnlock()
	sku, ok := s.skus[request.Sku]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	var certs []*pbc.Certificate
	for _, bundle := range request.Bundles {
		keyLabel, err := sku.config.GetUnsafeAttribute(bundle.KeyParams.KeyLabel)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to find key label %q in SKU configuration: %v", bundle.KeyParams.KeyLabel, err)
		}
		switch key := bundle.KeyParams.Key.(type) {
		case *pbc.SigningKeyParams_EcdsaParams:
			params := se.EndorseCertParams{
				KeyLabel:           keyLabel,
				SignatureAlgorithm: ecdsaSignatureAlgorithmFromHashType(key.EcdsaParams.HashType),
			}
			cert, err := sku.seHandle.EndorseCert(bundle.Tbs, params)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "could not endorse cert: %v", err)
			}
			certs = append(certs, &pbc.Certificate{Blob: cert})
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
	s.muSKU.RLock()
	defer s.muSKU.RUnlock()

	// Locate SKU config.
	sku, ok := s.skus[request.Sku]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	// Retrieve signing key label.
	keyLabel, err := sku.config.GetUnsafeAttribute(request.KeyParams.KeyLabel)
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
		asn1Pubkey, asn1Sig, err = sku.seHandle.EndorseData(request.Data, params)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not endorse data payload: %v", err)
		}
	default:
		return nil, status.Errorf(codes.Unimplemented, "unsupported key format")
	}

	return &pbs.EndorseDataResponse{
		Pubkey:    asn1Pubkey,
		Signature: asn1Sig,
	}, nil
}

func (s *server) initializeSKU(skuName string) error {
	s.muSKU.Lock()
	defer s.muSKU.Unlock()
	if _, ok := s.skus[skuName]; ok {
		return nil
	}

	configFilename := "sku_" + skuName + ".yml"

	var cfg skucfg.Config
	err := utils.LoadConfig(s.configDir, configFilename, &cfg)
	if err != nil {
		return fmt.Errorf("could not load config: %v", err)
	}

	var hsmPassword string
	if s.hsmPasswordFile != "" {
		val, err := utils.ReadFile(s.hsmPasswordFile)
		if err != nil {
			return fmt.Errorf("unable to read file: %q, error: %v", s.hsmPasswordFile, err)
		}
		hsmPassword = string(val)
	}

	if hsmPassword == "" {
		val, ok := os.LookupEnv("SPM_HSM_PIN_USER")
		if !ok {
			return fmt.Errorf("initializeSKU failed: Restart server with --hsm_pw or SPM_HSM_PIN_USER set environment.")
		}
		hsmPassword = val
	}

	log.Printf("Initializing symmetric keys: %v", cfg.SymmetricKeys)
	akeys := make([]string, len(cfg.SymmetricKeys))
	for i, key := range cfg.SymmetricKeys {
		akeys[i] = key.Name
	}

	log.Printf("Initializing private keys: %v", cfg.PrivateKeys)
	pkeys := make([]string, len(cfg.PrivateKeys))
	for i, key := range cfg.PrivateKeys {
		pkeys[i] = key.Name
	}

	log.Printf("Initializing public keys: %v", cfg.PublicKeys)
	pubKeys := make([]string, len(cfg.PublicKeys))
	for i, key := range cfg.PublicKeys {
		pubKeys[i] = key.Name
	}

	log.Printf("Initializing HSM: %v", cfg)
	// Create new instance of HSM.
	seHandle, err := se.NewHSM(se.HSMConfig{
		SOPath:        s.hsmSOLibPath,
		SlotID:        cfg.SlotID,
		HSMPassword:   hsmPassword,
		NumSessions:   cfg.NumSessions,
		SymmetricKeys: akeys,
		PrivateKeys:   pkeys,
		PublicKeys:    pubKeys,
	})
	if err != nil {
		return fmt.Errorf("fail to create an instance of HSM: %v", err)
	}

	// Load all certificates referenced in the SKU configuration.
	certs := make(map[string]*x509.Certificate)
	for _, cert := range cfg.Certs {
		c, err := utils.LoadCertFromFile(s.configDir, cert.Path)
		if err != nil {
			return fmt.Errorf("could not load cert: %v", err)
		}
		certs[cert.Name] = c
	}

	s.skus[skuName] = &skuState{
		config:   &cfg,
		certs:    certs,
		seHandle: seHandle,
	}
	return nil
}
