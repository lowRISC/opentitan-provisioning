// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package devid

import (
	"bytes"
	"testing"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const deviceIDHex = "0100000047425f54000000014742000000000000000790100500346400024001"

var hardwareOriginHex = []byte{
	0x01, 0x40, 0x02, 0x00,
	0x64, 0x34, 0x00, 0x05,
	0x10, 0x90, 0x07, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

func TestDevID(t *testing.T) {
	d, err := FromHex(deviceIDHex)
	if err != nil {
		t.Fatalf("Failed to decode device ID: %v", err)
	}
	if d == nil {
		t.Fatal("Decoded device ID is nil")
	}
	if d.HardwareOrigin == nil {
		t.Fatal("Decoded device ID hardware origin is nil")
	}

	if d.HardwareOrigin.SiliconCreatorId != dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON {
		t.Errorf("Expected SiliconCreatorId %v, got %v", dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON, d.HardwareOrigin.SiliconCreatorId)
	}

	if d.HardwareOrigin.ProductId != dpb.ProductId_PRODUCT_ID_EARLGREY_A1 {
		t.Errorf("Expected ProductId %v, got %v", dpb.ProductId_PRODUCT_ID_EARLGREY_A1, d.HardwareOrigin.ProductId)
	}
	if d.HardwareOrigin.DeviceIdentificationNumber != 0x7901005003464 {
		t.Errorf("Expected DeviceIdentificationNumber %v, got %x", 0x7901005003464, d.HardwareOrigin.DeviceIdentificationNumber)
	}
	if d.HardwareOrigin.CpReserved != 0x00000000 {
		t.Errorf("Expected CpReserved %v, got %v", 0x00000000, d.HardwareOrigin.CpReserved)
	}
	if d.SkuSpecific == nil {
		t.Fatal("Decoded device ID SKU specific is nil")
	}
	if len(d.SkuSpecific) != 16 {
		t.Fatalf("Expected SKU specific length 16, got %d", len(d.SkuSpecific))
	}
	h, err := DeviceIDToHex(d)
	if err != nil {
		t.Fatalf("Failed to encode device ID: %v", err)
	}
	if h != deviceIDHex {
		t.Errorf("Expected device ID hex %s, got %s", deviceIDHex, h)
	}
	hwRaw, err := HardwareOriginToRawBytes(d.HardwareOrigin)
	if err != nil {
		t.Fatalf("Failed to encode hardware origin: %v", err)
	}
	if len(hwRaw) != 16 {
		t.Fatalf("Expected hardware origin raw length 16, got %d", len(hwRaw))
	}
	if !bytes.Equal(hwRaw, hardwareOriginHex) {
		t.Errorf("Expected hardware origin raw %x, got %x", hardwareOriginHex, hwRaw)
	}
}
