// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package devid

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proto/validators"
)

type DeviceIDField struct {
	start int
	end   int
}

var (
	FieldHWOriginSICreatorID = DeviceIDField{0, 2}
	FieldHWOriginProductID   = DeviceIDField{2, 4}
	FieldDIN                 = DeviceIDField{4, 12}
	FieldReserved1           = DeviceIDField{12, 16}
	FieldSKUSpecific         = DeviceIDField{16, 32}
)

// FromRawBytes converts a byte slice to a DeviceId object.
// It expects the byte slice to be in little-endian format and of length 32
// bytes.
func FromRawBytes(raw []byte) (*dpb.DeviceId, error) {
	if len(raw) < 32 {
		return nil, fmt.Errorf("raw bytes length is less than 32")
	}

	siID := dpb.SiliconCreatorId(binary.LittleEndian.Uint16(raw[FieldHWOriginSICreatorID.start:FieldHWOriginSICreatorID.end]))
	pID := dpb.ProductId(binary.LittleEndian.Uint16(raw[FieldHWOriginProductID.start:FieldHWOriginProductID.end]))
	din := binary.LittleEndian.Uint64(raw[FieldDIN.start:FieldDIN.end])
	rsvd := binary.LittleEndian.Uint32(raw[FieldReserved1.start:FieldReserved1.end])

	deviceId := &dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           siID,
			ProductId:                  pID,
			DeviceIdentificationNumber: din,
			CpReserved:                 rsvd,
		},
		SkuSpecific: raw[FieldSKUSpecific.start:FieldSKUSpecific.end],
	}

	if err := validators.ValidateDeviceId(deviceId); err != nil {
		return nil, fmt.Errorf("error validating device ID: %v", err)
	}

	return deviceId, nil
}

// Reverses the byte slice in place.
// TODO(#155): Migrate to `slices.Reverse` in Go >= 1.21.
func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// FromHex converts a hex string to a DeviceId object.
// It expects the hex string to be in little-endian format and of length 64
// characters (32 bytes).
func FromHex(h string) (*dpb.DeviceId, error) {
	raw, err := hex.DecodeString(h)
	reverse(raw)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex string: %v", err)
	}
	return FromRawBytes(raw)
}

// DeviceIDToRawBytes converts a DeviceId object to a byte slice.
// It returns a byte slice of length 32 bytes in little-endian format.
func DeviceIDToRawBytes(d *dpb.DeviceId) ([]byte, error) {
	if err := validators.ValidateDeviceId(d); err != nil {
		return nil, fmt.Errorf("error validating device ID: %v", err)
	}

	raw := make([]byte, 32)
	binary.LittleEndian.PutUint16(raw[FieldHWOriginSICreatorID.start:FieldHWOriginSICreatorID.end], uint16(d.HardwareOrigin.SiliconCreatorId))
	binary.LittleEndian.PutUint16(raw[FieldHWOriginProductID.start:FieldHWOriginProductID.end], uint16(d.HardwareOrigin.ProductId))
	binary.LittleEndian.PutUint64(raw[FieldDIN.start:FieldDIN.end], d.HardwareOrigin.DeviceIdentificationNumber)
	binary.LittleEndian.PutUint32(raw[FieldReserved1.start:FieldReserved1.end], d.HardwareOrigin.CpReserved)
	copy(raw[FieldSKUSpecific.start:FieldSKUSpecific.end], d.SkuSpecific)

	return raw, nil
}

// DeviceIDToHex converts a DeviceId object to a hex string.
// It returns a hex string of length 64 characters (32 bytes) in little-endian
// format.
func DeviceIDToHex(d *dpb.DeviceId) (string, error) {
	raw, err := DeviceIDToRawBytes(d)
	if err != nil {
		return "", fmt.Errorf("error converting device ID to raw bytes: %v", err)
	}
	reverse(raw)
	return hex.EncodeToString(raw), nil
}

// HardwareOriginToRawBytes converts a HardwareOrigin object to a byte slice.
// It returns a byte slice of length 16 bytes in little-endian format.
func HardwareOriginToRawBytes(h *dpb.HardwareOrigin) ([]byte, error) {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint16(raw[FieldHWOriginSICreatorID.start:FieldHWOriginSICreatorID.end], uint16(h.SiliconCreatorId))
	binary.LittleEndian.PutUint16(raw[FieldHWOriginProductID.start:FieldHWOriginProductID.end], uint16(h.ProductId))
	binary.LittleEndian.PutUint64(raw[FieldDIN.start:FieldDIN.end], h.DeviceIdentificationNumber)
	binary.LittleEndian.PutUint32(raw[FieldReserved1.start:FieldReserved1.end], h.CpReserved)
	return raw, nil
}

// HardwareOriginToHex converts a HardwareOrigin object to a hex string.
// It returns a hex string of length 32 characters (16 bytes) in little-endian
// format.
func HardwareOriginToHex(h *dpb.HardwareOrigin) (string, error) {
	raw, err := HardwareOriginToRawBytes(h)
	if err != nil {
		return "", fmt.Errorf("error converting hardware origin to raw bytes: %v", err)
	}
	reverse(raw)
	return hex.EncodeToString(raw), nil
}
