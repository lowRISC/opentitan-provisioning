// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package skumgr implements SKU and secure element configuration management.
package skumgr

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/skucfg"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
)

// Sku contains the configuration and assets for a particular SKU.
type Sku struct {
	// Config contains the SKU configuration data.
	Config *skucfg.Config

	// Certs contains a map of certificates loaded at SKU init configuration time.
	// The key is the certificate name which can be referenced by clients.
	Certs map[string]*x509.Certificate

	// SeHandle is an instance of the secure element (HSM).
	SeHandle se.SE
}

// Manager manages the lifecycle of SKUs.
type Manager struct {
	// configDir points to the directory holding all SKU configuration files
	// and assets.
	configDir string

	// hsmSOLibPath points to the HSM dynamic library file path.
	hsmSOLibPath string

	// hsmPasswordFile holds the full file path of the HSM's password
	hsmPasswordFile string

	// skus contains initialized SKU specific configuration.
	skus map[string]*Sku

	// mu is a mutex to arbitrate SKU initialization access.
	mu sync.RWMutex
}

// Options contains configuration options for the Manager.
type Options struct {
	ConfigDir       string
	HSMSOLibPath    string
	HsmPasswordFile string
}

// NewManager creates a new SKU manager.
func NewManager(opts Options) *Manager {
	return &Manager{
		configDir:       opts.ConfigDir,
		hsmSOLibPath:    opts.HSMSOLibPath,
		hsmPasswordFile: opts.HsmPasswordFile,
		skus:            make(map[string]*Sku),
	}
}

// LoadSku initializes a SKU and returns its configuration.
// If the SKU is already loaded, it returns the existing instance.
func (m *Manager) LoadSku(skuName string) (*Sku, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sku, ok := m.skus[skuName]; ok {
		return sku, nil
	}

	configFilename := "sku_" + skuName + ".yml"

	var cfg skucfg.Config
	err := utils.LoadConfig(m.configDir, configFilename, &cfg)
	if err != nil {
		return nil, fmt.Errorf("could not load config: %v", err)
	}

	var hsmPassword string
	if m.hsmPasswordFile != "" {
		val, err := utils.ReadFile(m.hsmPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("unable to read file: %q, error: %v", m.hsmPasswordFile, err)
		}
		hsmPassword = string(val)
	}

	if hsmPassword == "" {
		val, ok := os.LookupEnv("SPM_HSM_PIN_USER")
		if !ok {
			val, ok := os.LookupEnv("HSMTOOL_PIN")
			if !ok {
				return nil, fmt.Errorf("LoadSku failed: set hsm_password_file or SPM_HSM_PIN_USER or HSMTOOL_PIN environment variable.")
			}
			hsmPassword = val
		} else {
			hsmPassword = val
		}
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
		SOPath:        m.hsmSOLibPath,
		SlotID:        cfg.SlotID,
		HSMPassword:   hsmPassword,
		NumSessions:   cfg.NumSessions,
		SymmetricKeys: akeys,
		PrivateKeys:   pkeys,
		PublicKeys:    pubKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("fail to create an instance of HSM: %v", err)
	}

	// Load all certificates referenced in the SKU configuration.
	log.Printf("Initializing certificates: %v", cfg.Certs)
	certs := make(map[string]*x509.Certificate)
	for _, cert := range cfg.Certs {
		c, err := utils.LoadCertFromFile(m.configDir, cert.Path)
		if err != nil {
			return nil, fmt.Errorf("could not load cert: %v", err)
		}
		certs[cert.Name] = c
	}

	sku := &Sku{
		Config:   &cfg,
		Certs:    certs,
		SeHandle: seHandle,
	}
	m.skus[skuName] = sku
	return sku, nil
}

// GetSku returns a loaded SKU.
func (m *Manager) GetSku(skuName string) (*Sku, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sku, ok := m.skus[skuName]
	return sku, ok
}
