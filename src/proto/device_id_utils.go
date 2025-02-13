// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package device_id_utils

import (
	"fmt"
	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
)

const (
	ReservedDeviceIdField = 0
)

// Converts a DeviceId into a hex string.
func DeviceIdToHexString(di *dpb.DeviceId) string {
	return fmt.Sprintf("0x%x%08x%016x%08x%08x",
		di.SkuSpecific,
		ReservedDeviceIdField,
		uint64(di.HardwareOrigin.DeviceIdentificationNumber),
		uint16(di.HardwareOrigin.ProductId),
		uint16(di.HardwareOrigin.SiliconCreatorId),
	)
}
