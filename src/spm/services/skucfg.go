// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package skucfg provides the configuration for a SKU.
package skucfg

import (
	"fmt"

	pbcommon "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
)

// AttrName is an attribute name.
type AttrName string

const (
	AttrNameSymmetricWrappingMethod AttrName = "symmetricWrappingMethod"
)

// WrappingMethod provides the wrapping method for symmetric keys.
type WrappingMethod string

const (
	WrappingMethodNone     WrappingMethod = "none"
	WrappingMethodRSAPKCS1                = "rsa-pkcs"
	WrappingMethodRSAOAEP                 = "rsa-oaep"
)

type Config struct {
	Sku             string                    `yaml:"sku"`
	SlotID          int                       `yaml:"slotId"`
	NumSessions     int                       `yaml:"numSessions"`
	SymmetricKeys   []SymmetricKey            `yaml:"symmetricKeys"`
	PrivateKeys     []PrivateKey              `yaml:"privateKeys"`
	PublicKeys      []PublicKey               `yaml:"publicKeys"`
	Keys            []Key                     `yaml:"keyWrapConfig"`
	Certs           []Certificate             `yaml:"certs"`
	CertTemplates   []Certificate             `yaml:"certTemplates"`
	CertTemplateSan CertificateSubjectAltName `yaml:"certTemplateSAN"`
	Attributes      map[string]string         `yaml:"attributes"`
}

// KeyType is a type of key to generate.
type KeyType string

// KeyName represents signature algorithm.
type KeyName int

const (
	Secp256r1 KeyName = iota
	Secp384r1
	RSA2048
	RSA3072
	RSA4096
)

type Key struct {
	Type KeyType           `yaml:"type"`
	Size int               `yaml:"size"`
	Name KeyName           `yaml:"name"`
	Hash pbcommon.HashType `yaml:"hash"`
	Exp  []byte            `yaml:"exp"`
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

type CertificateSubjectAltName struct {
	Manufacturer string `yaml:"tpmManufacturer"`
	Model        string `yaml:"tpmModel"`
	Version      string `yaml:"tpmVersion"`
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
