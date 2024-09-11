// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package device_data contains device variables.
package device_testdata

import (
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const (
	DeviceIdSkuSpecificLen = 128
)

var (
	hwOriginOk = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
		DeviceIdentificationNumber: 0,
	}
	hwOriginBadSiliconCreatorId = dpb.HardwareOrigin{
		SiliconCreatorId:           2,
		ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_A1,
		DeviceIdentificationNumber: 0,
	}
	hwOriginBadProductId = dpb.HardwareOrigin{
		SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON,
		ProductId:                  0x10000,
		DeviceIdentificationNumber: 0,
	}
)

func NewDeviceID() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen),
	}
}

func NewDeviceIDSkuTooLong() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen+1),
	}
}

func NewDeviceIDMissingSku() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &hwOriginOk,
		SkuSpecific:    nil, // Empty SkuSpecific is OK.
	}
}

func NewDeviceIdBadOrigin() *dpb.DeviceId {
	return &dpb.DeviceId{
		HardwareOrigin: &hwOriginBadSiliconCreatorId,
		SkuSpecific:    make([]byte, DeviceIdSkuSpecificLen),
	}
}
