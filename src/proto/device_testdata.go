// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package device_data contains data objects for testing.
package device_testdata

import (
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	rpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
)

const (
	DeviceIdSkuSpecificLenInBytes = 16
	WrappedRmaTokenLenInBytes     = 27 // 16 bytes of token + 11 PKCS#1v1.5 padding
	MaxPersoTlvDataLenInBytes     = 32768
)

var (
	// HardwareOrigin objects.
	// TODO: add varying device identification numbers to test cases
	HwOriginOk = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
		DeviceIdentificationNumber: 0xbeefcafefeed1234,
	}
	HwOriginBadSiliconCreatorId = dpb.HardwareOrigin{
		SiliconCreatorId:           2,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
		DeviceIdentificationNumber: 0,
	}
	HwOriginBadProductId = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON,
		ProductId:                  0x10000,
		DeviceIdentificationNumber: 0,
	}

	// DeviceId objects.
	DeviceIdOk = dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes),
	}
	DeviceIdOkMissingSkuSpecific = dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    nil, // Empty SkuSpecific is OK.
	}
	DeviceIdBadSiliconCreatorId = dpb.DeviceId{
		HardwareOrigin: &HwOriginBadSiliconCreatorId,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes),
	}
	DeviceIdBadProductId = dpb.DeviceId{
		HardwareOrigin: &HwOriginBadProductId,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes),
	}
	DeviceIdSkuTooLong = dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes+1),
	}

	// DeviceData objects.
	// TODO(timothytrippel): add metadata fields to validate?
	DeviceDataOk = dpb.DeviceData{
		DeviceId:              &DeviceIdOk,
		DeviceLifeCycle:       dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
		WrappedRmaUnlockToken: make([]byte, WrappedRmaTokenLenInBytes),
		PersoTlvData:          make([]byte, MaxPersoTlvDataLenInBytes),
	}
	DeviceDataBadLifeCycle = dpb.DeviceData{
		DeviceId:              &DeviceIdOk,
		DeviceLifeCycle:       dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_UNSPECIFIED,
		WrappedRmaUnlockToken: make([]byte, WrappedRmaTokenLenInBytes),
		PersoTlvData:          make([]byte, MaxPersoTlvDataLenInBytes),
	}
	DeviceDataWrappedRmaUnlockTokenTooLarge = dpb.DeviceData{
		DeviceId:              &DeviceIdOk,
		DeviceLifeCycle:       dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
		WrappedRmaUnlockToken: make([]byte, WrappedRmaTokenLenInBytes+1),
		PersoTlvData:          make([]byte, MaxPersoTlvDataLenInBytes),
	}
	DeviceDataPersoTlvDataTooLarge = dpb.DeviceData{
		DeviceId:              &DeviceIdOk,
		DeviceLifeCycle:       dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
		WrappedRmaUnlockToken: make([]byte, WrappedRmaTokenLenInBytes),
		PersoTlvData:          make([]byte, MaxPersoTlvDataLenInBytes+1),
	}

	// RegistryRecord objects.
	RegistryRecordOk = rpb.RegistryRecord{
		DeviceId: diu.DeviceIdToHexString(&DeviceIdOk),
		Sku:      "sival",
		Version:  0,
		Data:     make([]byte, 1000),
	}
	RegistryRecordEmptyDeviceId = rpb.RegistryRecord{
		DeviceId: "",
		Sku:      "sival",
		Version:  0,
		Data:     make([]byte, 1000),
	}
	RegistryRecordEmptySku = rpb.RegistryRecord{
		DeviceId: diu.DeviceIdToHexString(&DeviceIdOk),
		Sku:      "",
		Version:  0,
		Data:     make([]byte, 1000),
	}
	RegistryRecordEmptyData = rpb.RegistryRecord{
		DeviceId: diu.DeviceIdToHexString(&DeviceIdOk),
		Sku:      "sival",
		Version:  0,
		Data:     make([]byte, 0),
	}
)

func NewDeviceID() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes),
	}
}

func NewDeviceIDSkuTooLong() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes+1),
	}
}

func NewDeviceIDMissingSku() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &HwOriginOk,
		SkuSpecific:    nil, // Empty SkuSpecific is OK.
	}
}

func NewDeviceIdBadOrigin() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &HwOriginBadSiliconCreatorId,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLenInBytes),
	}
}

func NewRegistryRecordOk(deviceID *dpb.DeviceId) rpb.RegistryRecord {
	return rpb.RegistryRecord{
		DeviceId: diu.DeviceIdToHexString(deviceID),
		Sku:      "sival",
		Version:  0,
		Data:     make([]byte, 1000),
	}
}
