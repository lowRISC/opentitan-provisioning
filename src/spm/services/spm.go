// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package spm implements the gRPC Spm server interface.
package spm

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/certloader"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service/session_token"
	"github.com/lowRISC/opentitan-provisioning/src/utils"

	pbc "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	pbe "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	pbr "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/rsa_ssa_pcks1_go_pb"

	pbw "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/wrap_go_pb"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
)

// Options contain configuration options for the SPM service.
type Options struct {
	// HSMSOLibPath contains the path to the PCKS#11 interface used to connect
	// to the HSM.
	HSMSOLibPath string

	// SPMConfigPath contains the path to the SPM YAML configuration file.
	SPMConfigFile string

	// SPMConfigDir contains the path to the SPM configuration directory. All
	// files referenced in the configuration YAML file `SPMConfigFile` must be
	// relative to this path.
	SPMConfigDir string

	// HsmType contains the type of the HSM (Soft or Hardware)
	HsmType int64

	// File contains the full file path of the HSM's password
	HsmPWFile string

	// MSConfigFile contains the path to MSClient JSON configuration file.
	MSConfigFile string
}

// server is the server object.
type server struct {
	// Instance of the tpm certificate template builder.
	loader *certloader.Loader

	// configDir points to the directory holding all SKU configuration files
	// and assets.
	configDir string

	// hsmSOLibPath points to the HSM dynamic library file path.
	hsmSOLibPath string

	// hsmPasswordFile holds the full file path of the HSM's password
	hsmPasswordFile string

	// hsmType contains the type of the HSM (SoftHSM or NetworkHSM)
	hsmType pk11.HSMType

	// skus contains SKU specific configuration only visible to the SPM
	// server.
	skus map[string]*skuState

	// authCfg contains the configuration of the authentication token
	authCfg *AuthConfig

	// muSKU is a mutex use to arbitrate SKU initialization access.
	muSKU sync.RWMutex
}

type SkuAuthConfig struct {
	SkuAuth string   `yaml:"skuAuth"`
	Methods []string `yaml:"methods"`
}

type AuthConfig struct {
	SkuAuthCfgList map[string]SkuAuthConfig `yaml:"skuAuthCfgList"`
}

type Config struct {
	Sku             string                               `yaml:"sku"`
	SlotID          int                                  `yaml:"slotId"`
	NumSessions     int                                  `yaml:"numSessions"`
	WrapKeyName     string                               `yaml:"wrapKeyName"`
	CaKeyName       string                               `yaml:"caKeyName"`
	CertTemplate    []certloader.CertificateConfig       `yaml:"certTemplate"`
	CertTemplateSan certloader.CertificateSubjectAltName `yaml:"certTemplateSAN"`
	Keys            []certloader.Key                     `yaml:"keyWrapConfig"`
	RootCaPath      string                               `yaml:"rootCAPath"`
}

type skuState struct {
	// config contains the SKU configuration data loaded by `InitSession()`.
	config *Config

	// rootCACert is the root CA certificate associated with the SKU.
	rootCACert *x509.Certificate

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
		log.Printf("config directory does not exist: %q, error: %v", opts.SPMConfigDir, err)
		return nil, fmt.Errorf("config directory does not exist: %q, error: %v", opts.SPMConfigDir, err)
	}

	// TODO: make this runtime configurable
	filename := "sku_auth.yml"
	var config AuthConfig
	err := utils.LoadConfig(opts.SPMConfigDir, filename, &config)
	if err != nil {
		log.Printf("could not load config: %v", err)
		return nil, fmt.Errorf("could not load sku auth config: %v", err)
	}

	session_token.NewSessionTokenInstance()

	return &server{
		loader:          certloader.New(),
		configDir:       opts.SPMConfigDir,
		hsmSOLibPath:    opts.HSMSOLibPath,
		hsmPasswordFile: opts.HsmPWFile,
		hsmType:         pk11.HSMType(opts.HsmType),
		skus:            make(map[string]*skuState),
		authCfg: &AuthConfig{
			SkuAuthCfgList: config.SkuAuthCfgList,
		},
	}, nil
}

func (s *server) initSku(sku string) (string, error) {
	token, err := generateSessionToken(TokenSize)
	if err != nil {
		log.Printf("failed to generate session token: %v", err)
		return "", status.Errorf(codes.NotFound, "failed to generate session token: %v", err)
	}

	if strings.HasPrefix(sku, "tpm_") {
		log.Printf("SPM.InitSession Response - TPM Token")
		err = s.initializeSKU(sku)
		if err != nil {
			log.Printf("failed to initialize sku: %v", err)
			return "", status.Errorf(codes.Internal, "failed to initialize sku")
		}
	}
	return token, nil
}

// findSkuAuth returns an empty sku auth config, if nor sku or a family sku can be found
// in the map config, otherwise the relavent sku auth config will be return.
func (s *server) findSkuAuth(sku string) (SkuAuthConfig, bool) {
	skuAuthConfig := SkuAuthConfig{}
	if skuAuthConfig, found := s.authCfg.SkuAuthCfgList[sku]; found {
		return skuAuthConfig, true
	}

	// Iterate over the skus in the map and search for the family sku
	for familySku := range s.authCfg.SkuAuthCfgList {
		if strings.HasPrefix(sku, familySku) {
			skuAuthConfig = s.authCfg.SkuAuthCfgList[familySku]
			return skuAuthConfig, true
		}
	}

	return SkuAuthConfig{}, false
}

func (s *server) InitSession(ctx context.Context, request *pbp.InitSessionRequest) (*pbp.InitSessionResponse, error) {
	log.Printf("SPM.InitSessionRequest - Sku:%q", request.Sku)

	// search sku & products
	var skuAuthConfig SkuAuthConfig
	var found bool
	if s.authCfg != nil {
		if skuAuthConfig, found = s.findSkuAuth(request.Sku); !found {
			return nil, status.Errorf(codes.Internal, "unknown sku: %q", request.Sku)
		}
		err := utils.CompareHashAndPassword(skuAuthConfig.SkuAuth, request.SkuAuth)
		if err != nil {
			log.Printf("incorrect sku hash authentication: %q", request.SkuAuth)
			return nil, status.Errorf(codes.Internal, "incorrect sku authentication %q", request.SkuAuth)
		}
	} else {
		return nil, status.Errorf(codes.Internal, "authentication config pointer is nil")
	}

	token, err := s.initSku(request.Sku)
	if err != nil {
		log.Printf("failed to initialize sku: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to initialize sku: %v", err)
	}

	return &pbp.InitSessionResponse{
		SkuSessionToken: token,
		AuthMethods:     skuAuthConfig.Methods,
	}, nil
}

// CreateKeyAndCert generates a set of wrapped keys for a given Device.
func (s *server) CreateKeyAndCert(ctx context.Context, request *pbp.CreateKeyAndCertRequest) (*pbp.CreateKeyAndCertResponse, error) {
	log.Printf("SPM.CreateKeyAndCertRequest - Sku:%q", request.Sku)

	s.muSKU.RLock()
	defer s.muSKU.RUnlock()
	sku, ok := s.skus[request.Sku]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unable to find sku %q. Try calling InitSession first", request.Sku)
	}

	serialNumber := utils.NumToStr(request.SerialNumber, BigEndian)
	signParams, err := s.getSigningParams(sku, serialNumber)
	if err != nil {
		return nil, status.Errorf(codes.OutOfRange, "could not retrieve cert template for device: %s", err)
	}

	certs, err := sku.seHandle.GenerateKeyPairAndCert(sku.rootCACert, signParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not mint certificate: %s", err)
	}

	endorsedKeys, err := s.makeEndorsedKeys(sku, certs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not make endorsed key: %s", err)
	}

	log.Println("[CreateKeyAndCertRequest] Finished")

	return &pbp.CreateKeyAndCertResponse{
		Keys: endorsedKeys,
	}, nil
}

func (s *server) initializeSKU(skuName string) error {
	s.muSKU.Lock()
	defer s.muSKU.Unlock()
	if _, ok := s.skus[skuName]; ok {
		return nil
	}

	configFilename := "sku_" + skuName + ".yml"

	var cfg Config
	err := utils.LoadConfig(s.configDir, configFilename, &cfg)
	if err != nil {
		log.Printf("could not load config: %v", err)
		return fmt.Errorf("could not load config: %v", err)
	}

	rootCACert, err := utils.LoadCertFromFile(s.configDir, cfg.RootCaPath)
	if err != nil {
		log.Printf("could not load root ca cert: %v", err)
		return fmt.Errorf("could not load root ca cert: %v", err)
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

	// Create new instance of HSM (KT is empty since there no need for it in the TPM)
	seHandle, err := se.NewHSM(se.HSMConfig{
		SOPath:      s.hsmSOLibPath,
		SlotID:      cfg.SlotID,
		HSMPassword: hsmPassword,
		NumSessions: cfg.NumSessions,
		KGName:      cfg.WrapKeyName,
		KcaName:     cfg.CaKeyName,
		HSMType:     s.hsmType,
	})
	if err != nil {
		log.Printf("fail to create an instance of HSM: %v", err)
		return fmt.Errorf("fail to create an instance of HSM: %v", err)
	}

	s.skus[skuName] = &skuState{
		config:     &cfg,
		rootCACert: rootCACert,
		seHandle:   seHandle,
	}
	return nil
}

func buildCertWithSerial(template *x509.Certificate, skuSerialNumber string) (*x509.Certificate, error) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			SerialNumber: skuSerialNumber,
		},
		// other fields...
		Issuer:                template.Issuer,
		SerialNumber:          template.SerialNumber,
		NotBefore:             template.NotBefore,
		NotAfter:              template.NotAfter,
		BasicConstraintsValid: template.BasicConstraintsValid, //true,
		IsCA:                  template.IsCA,                  //false,
		MaxPathLenZero:        template.MaxPathLenZero,        //false,
		KeyUsage:              template.KeyUsage,
		IssuingCertificateURL: template.IssuingCertificateURL,
		ExtraExtensions:       template.ExtraExtensions,
		UnknownExtKeyUsage:    template.UnknownExtKeyUsage,
	}
	return cert, nil
}

// getSigningParams returns SigningParams from skus
func (s *server) getSigningParams(sku *skuState, subjectSerialNumber string) ([]se.SigningParams, error) {
	var keyParams any
	var signParams []se.SigningParams

	// Cert serial number is 10 bytes length positive number
	CertSerialNumbers := make([]*big.Int, 0)
	for i, key := range sku.config.Keys {
		serialNumber, err := sku.seHandle.GenerateRandom(EKCertSerialNumberSize)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "could not generate random data: %v", err)
		}

		// The serial number MUST be a positive integer.
		serialNumber[0] &= 0x7F
		// In case of leading zero set the msb to "1".
		if serialNumber[0] == 0 {
			serialNumber[0] = 1
		}
		CertSerialNumber := big.NewInt(0)
		CertSerialNumber.SetBytes(serialNumber)
		CertSerialNumbers = append(CertSerialNumbers, CertSerialNumber)

		fmt.Println("getSigningParams key = ", key)
		log.Printf("getSigningParams key =%q", key)
		switch key.Name {
		case certloader.RSA2048:
			keyParams = se.RSAParams{key.Size, int(big.NewInt(0).SetBytes(key.Exp).Uint64())}
		case certloader.RSA3072:
			keyParams = se.RSAParams{key.Size, int(big.NewInt(0).SetBytes(key.Exp).Uint64())}
		case certloader.RSA4096:
			keyParams = se.RSAParams{key.Size, int(big.NewInt(0).SetBytes(key.Exp).Uint64())}
		case certloader.Secp256r1:
			keyParams = elliptic.P256()
		case certloader.Secp384r1:
			keyParams = elliptic.P384()
		default:
			return nil, status.Errorf(codes.Unimplemented, "unsupported key")
		}

		// Load from SKU configuration blob as this certificate is
		// generated at SKU creation time.
		template, err := s.loader.LoadTemplateFromFile(s.configDir, sku.config.CertTemplate[i].CertPath)
		if err != nil {
			return nil, status.Errorf(codes.OutOfRange, "could not retrieve cert template for device: %v", err)
		}

		template.SerialNumber = CertSerialNumbers[i]
		template.NotBefore = time.Now()
		if subjectSerialNumber != "" {
			template.NotAfter = time.Now().AddDate(80, 0, 0)
		} else {
			template.NotAfter = time.Now().AddDate(20, 0, 0)
		}

		issuingCertificateURL, err := certloader.UpdateIssuingCertificateURL(template.IssuingCertificateURL[0], sku.config.RootCaPath)
		if err != nil {
			return nil, err
		}

		template.IssuingCertificateURL = []string{
			issuingCertificateURL,
		}

		subjectAltName, err := certloader.BuildSubjectAltName(sku.config.CertTemplateSan)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{
			subjectAltName,
		}

		cert, err := buildCertWithSerial(template, subjectSerialNumber)
		if err != nil {
			return nil, err
		}
		signParam := se.SigningParams{cert, keyParams}
		signParams = append(signParams, signParam)
	}
	return signParams, nil
}

// ecKeyNameFromInt returns the ec curve name
func ecKeyNameFromInt(index certloader.KeyName) pbcommon.EllipticCurveType {
	switch index {
	case certloader.Secp256r1:
		return pbcommon.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P256
	case certloader.Secp384r1:
		return pbcommon.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P384
	default:
		return pbcommon.EllipticCurveType_ELLIPTIC_CURVE_TYPE_UNSPECIFIED
	}
}

// makeEndorsedKeys returns list of endorse keys
func (s *server) makeEndorsedKeys(sku *skuState, certs []se.CertInfo) ([]*pbp.EndorsedKey, error) {
	var endorsedKey *pbp.EndorsedKey
	var endorsedKeys []*pbp.EndorsedKey
	endorsedKeys = make([]*pbp.EndorsedKey, 0, len(endorsedKeys))

	mode := pbw.WrappingMode(0)

	switch s.hsmType {
	case pk11.HSMTypeSoft:
		mode = pbw.WrappingMode_WRAPPING_MODE_AES_KWP
	case pk11.HSMTypeHW:
		mode = pbw.WrappingMode_WRAPPING_MODE_AES_GCM
	}

	for i, cert := range certs {
		key := sku.config.Keys[i]
		switch {
		case key.Type == "RSA":
			endorsedKey = &pbp.EndorsedKey{
				Cert: &pbc.Certificate{Blob: cert.Cert},
				WrappedKey: &pbw.WrappedKey{
					Mode:    mode,
					Payload: cert.WrappedKey,
					KeyFormat: &pbw.WrappedKey_RsaSsaPcks1{
						&pbr.RsaSsaPkcs1KeyFormat{
							Params: &pbr.RsaSsaPkcs1Params{
								HashType: key.Hash,
							},
							ModulusSizeInBits: uint32(key.Size),
							PublicExponent:    key.Exp,
						},
					},
					Iv: cert.Iv,
				},
			}
		case key.Type == "ECC":
			endorsedKey = &pbp.EndorsedKey{
				Cert: &pbc.Certificate{Blob: cert.Cert},
				WrappedKey: &pbw.WrappedKey{
					Mode:    mode,
					Payload: cert.WrappedKey,
					KeyFormat: &pbw.WrappedKey_Ecdsa{
						&pbe.EcdsaKeyFormat{
							Params: &pbe.EcdsaParams{
								HashType: key.Hash,
								Curve:    ecKeyNameFromInt(key.Name),
								Encoding: pbe.EcdsaSignatureEncoding_ECDSA_SIGNATURE_ENCODING_IEEE_P1363,
							},
						},
					},
					Iv: cert.Iv,
				},
			}
		default:
			return nil, status.Errorf(codes.Internal, "unsupported key type")
		}
		endorsedKeys = append(endorsedKeys, endorsedKey)
	}
	return endorsedKeys, nil
}
