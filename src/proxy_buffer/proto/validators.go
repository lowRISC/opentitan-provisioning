// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package validators provides validation routines for OT provisioning proto validators.

package validators

import (
	"fmt"

	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

// ValidateDeviceRegistrationRequest performs invariant checks for a
// DeviceRegistrationRequest that protobuf syntax cannot capture.
func ValidateDeviceRegistrationRequest(request *pb.DeviceRegistrationRequest) error {
	// Device IDs will be validated by the PA, only check if device ID string is empty.
	if request.Record.DeviceId == "" {
		return fmt.Errorf("Invalid DeviceRegistrationRequest; DeviceId empty")
	}
	// SKU strings will be validated by the PA, only check if SKU string is empty.
	if request.Record.Sku == "" {
		return fmt.Errorf("Invalid DeviceRegistrationRequest; SKU empty")
	}
	// Data fields will be validated by the PA, only check if field is empty.
	if len(request.Record.Data) == 0 {
		return fmt.Errorf("Invalid DeviceRegistrationRequest; Data empty")
	}
	return nil
}

func validateDeviceRegistrationStatus(status pb.DeviceRegistrationStatus) error {
	switch status {
	case
		pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
		pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
		pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BUFFER_FULL:
		return nil
	default:
		return fmt.Errorf("Invalid DeviceRegistrationStatus: %v", status)
	}
}

// ValidateDeviceRegistrationResponse performs invariant checks for a
// DeviceRegistrationResponse that protobuf syntax cannot capture.
func ValidateDeviceRegistrationResponse(response *pb.DeviceRegistrationResponse) error {
	if err := validateDeviceRegistrationStatus(response.Status); err != nil {
		return err
	}
	if response.DeviceId == "" {
		return fmt.Errorf("Invalid DeviceRegistrationResponse; DeviceId empty")
	}

	return nil
}
