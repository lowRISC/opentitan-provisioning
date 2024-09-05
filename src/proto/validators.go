// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package validators provides validation routines for OT provisioning proto validators.
//
// See:
//   - https://docs.google.com/document/d/1dE7vR791Atp7Wu7Ss90K1MvdyoroouSHPdq_RXQ2R8I#bookmark=id.n9feo7yvyhle
//     FIXME: Replace above with a pointer to markdown TBD.
//   -  https://docs.opentitan.org/doc/security/specs/identities_and_root_keys#device-identifier
package validators

import (
	"crypto/x509"
	"fmt"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const (
	DeviceIdSkuSpecificLen  = 128
	MinDeviceDataPayloadLen = 256
	MaxDeviceDataPayloadLen = 2048
)

// ValidateSiliconCreator checks a SiliconCreator value for validity.
func ValidateSiliconCreator(sc dpb.SiliconCreator) error {
	switch sc {
	case dpb.SiliconCreator_SILICON_CREATOR_TEST:
		return nil
	}
	return fmt.Errorf("Invalid SiliconCreator: %v", sc)
}

// validate16Bits checks that a uint32 would fit into 16 bits.
func validate16Bits(val uint32) error {
	if val != uint32(uint16(val)) {
		return fmt.Errorf("Value outside 16-bit range: %v", val)
	}
	return nil
}

// ValidateDeviceType performs invariant checks for a DeviceType that
// protobuf syntax cannot capture.
func ValidateDeviceType(dt *dpb.DeviceType) error {
	if err := ValidateSiliconCreator(dt.SiliconCreator); err != nil {
		return err
	}
	return validate16Bits(dt.ProductIdentifier)
}

// ValidateHardwareOrigin performs invariant checks for a
// HardwareOrigin that protobuf syntax cannot capture.
func ValidateHardwareOrigin(ho *dpb.HardwareOrigin) error {
	if err := ValidateDeviceType(ho.DeviceType); err != nil {
		return err
	}
	// FIXME: Validate ho.DeviceIdentificationNumber
	return nil
}

// ValidateDeviceId performs invariant checks for a DeviceId that
// protobuf syntax cannot capture.
func ValidateDeviceId(di *dpb.DeviceId) error {
	if err := ValidateHardwareOrigin(di.HardwareOrigin); err != nil {
		return err
	}

	// len(di.SkuSpecific) == 0 ==> (optional) field not supplied,
	// which is considered valid.
	if len(di.SkuSpecific) != 0 && len(di.SkuSpecific) != DeviceIdSkuSpecificLen {
		return fmt.Errorf("Invalid SkuSpecific string length: %v", len(di.SkuSpecific))
	}

	// FIXME: Validate di.crc32
	return nil
}

// DeviceIdToString injectively converts a (valid!) DeviceId into a deterministic string.
func DeviceIdToString(di *dpb.DeviceId) string {
	return fmt.Sprintf("DeviceId:%d:%x:%x:%x",
		di.HardwareOrigin.DeviceType.SiliconCreator,
		di.HardwareOrigin.DeviceType.ProductIdentifier,
		di.HardwareOrigin.DeviceIdentificationNumber,
		di.SkuSpecific)
}

// ValidateDeviceIdPub performs invariant checks for a DeviceIdPub
// that protobuf syntax cannot capture.
//
// See https://pkg.go.dev/crypto/x509#CreateCertificate and
// https://pkg.go.dev/crypto/x509#ParseCertificate for details.
func ValidateDeviceIdPub(c *dpb.DeviceIdPub) error {
	// As far as this code is concerned, it's valid if it parses
	// without error.
	//
	// TODO: This should probably be validating against some
	// limited set of profiles.  Need to determine which profiles,
	// maybe changing the signature of this function accordingly.
	_, err := x509.ParseCertificate(c.Blob)
	return err
}

// validateDeviceIdPubs performs invariant checks that protobuf syntax
// cannot capture on a list of Certificates.
func validateDeviceIdPubs(certs []*dpb.DeviceIdPub) error {
	for _, cert := range certs {
		if err := ValidateDeviceIdPub(cert); err != nil {
			return err
		}
	}

	return nil
}

// validatePayload does a length check payload object ([]byte).  Since
// a payload is optional, 0-length is considered valid.
func validatePayload(payload []byte) error {
	// len(payload) == 0 ==> (optional) field not supplied,
	// which is considered valid.
	l := len(payload)
	if l != 0 && (l < MinDeviceDataPayloadLen || l > MaxDeviceDataPayloadLen) {
		return fmt.Errorf("Invalid Payload length: %v", l)
	}

	return nil
}

// ValidateDeviceLifeCycle checks a life cycle value for validity.
func ValidateDeviceLifeCycle(lc dpb.DeviceLifeCycle) error {
	switch lc {
	case
		dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
		dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_DEV:
		return nil
	default:
		return fmt.Errorf("Invalid DeviceLifeCycle: %v", lc)
	}
}

// ValidateDeviceData performs invariant checks for a DeviceData that
// protobuf syntax cannot capture.
func ValidateDeviceData(dd *dpb.DeviceData) error {
	if err := validateDeviceIdPubs(dd.DeviceIdPubs); err != nil {
		return err
	}

	if err := validatePayload(dd.Payload); err != nil {
		return err
	}

	return ValidateDeviceLifeCycle(dd.DeviceLifeCycle)
}
