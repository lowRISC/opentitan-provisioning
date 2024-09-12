// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package device_data contains data objects for testing.
package device_testdata

import (
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const (
	DeviceIdSkuSpecificLenInBytes  = 16
	MaxDeviceDataPayloadLenInBytes = 8192
)

var (
	// HardwareOrigin objects.
	// TODO: add varying device identification numbers to test cases
	HwOriginOk = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
		DeviceIdentificationNumber: 0,
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
	// TODO: add deviceIdBadCrc, which would have a bad Crc32 field.

	// DeviceData objects.
	DeviceDataOk = dpb.DeviceData{
		Payload:         make([]byte, MaxDeviceDataPayloadLenInBytes),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
	}
	DeviceDataBadPayloadTooLarge = dpb.DeviceData{
		Payload:         make([]byte, MaxDeviceDataPayloadLenInBytes+1),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
	}
	DeviceDataBadLifeCycle = dpb.DeviceData{
		Payload:         make([]byte, 0),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_UNSPECIFIED,
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
