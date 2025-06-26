// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package skucfg provides the configuration for a SKU.
package skucfg

import (
	"fmt"
)

// AttrName is an attribute name.
type AttrName string

const (
	AttrNameSeedSecHi                AttrName = "SeedSecHi"
	AttrNameSeedSecLo                         = "SeedSecLo"
	AttrNameWrappingKeyLabel                  = "WrappingKeyLabel"
	AttrNameWrappingMechanism                 = "WrappingMechanism"
	AttrNameWASKeyLabel                       = "WASKeyLabel"
	AttrNameWASDisable                        = "WASDisable"
	AttrNameCertChainDiceLeaf                 = "CertChainDiceLeaf"
	AttrNameOwnerFirmwareBootMessage          = "OwnerFirmwareBootMessage"
)

// WrappingMechanism provides the wrapping method for symmetric keys.
type WrappingMechanism string

const (
	WrappingMechanismNone     WrappingMechanism = "none"
	WrappingMechanismAESGCM                     = "AesGcm"
	WrappingMechanismAESKWP                     = "AesKwp"
	WrappingMechanismRSAOAEP                    = "RsaOaep"
	WrappingMechanismRSAPKCS1                   = "RsaPkcs"
)

type Config struct {
	Sku           string            `yaml:"sku"`
	SlotID        int               `yaml:"slotId"`
	NumSessions   int               `yaml:"numSessions"`
	SymmetricKeys []SymmetricKey    `yaml:"symmetricKeys"`
	PrivateKeys   []PrivateKey      `yaml:"privateKeys"`
	PublicKeys    []PublicKey       `yaml:"publicKeys"`
	Certs         []Certificate     `yaml:"certs"`
	Attributes    map[string]string `yaml:"attributes"`
}

type SymmetricKey struct {
	Name string `yaml:"name"`
}

type PublicKey struct {
	Name string `yaml:"name"`
}

type PrivateKey struct {
	Name          string `yaml:"name"`
	EnsorsingCert string `yaml:"endorsingCert"`
}

type Certificate struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type SkuAuth struct {
	SkuAuth string   `yaml:"skuAuth"`
	Methods []string `yaml:"methods"`
}

type Auth struct {
	SkuAuthCfgList map[string]SkuAuth `yaml:"skuAuthCfgList"`
}

// GetAttribute returns the value of the attribute with the given name.
func (c *Config) GetAttribute(name AttrName) (string, error) {
	attr, ok := c.Attributes[string(name)]
	if !ok {
		return "", fmt.Errorf("attribute %s not found", name)
	}
	return attr, nil
}

// GetUnsafeAttribute returns the value of the attribute with the given name.
// This function is labeled as unsafe because it does not check if the
// attribute is part of the allow-list `AttrName`. It is the caller's
// responsibility to ensure that the attribute is safe to use.
func (c *Config) GetUnsafeAttribute(name string) (string, error) {
	attr, ok := c.Attributes[name]
	if !ok {
		return "", fmt.Errorf("attribute %s not found", name)
	}
	return attr, nil
}
