// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package validators provides validation routines for OT provisioning proto validators.

package validators

import (
	"fmt"

	common_validators "github.com/lowRISC/opentitan-provisioning/src/proto/validators"
	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

// ValidateDeviceRegistrationRequest performs invariant checks for a
// DeviceRegistrationRequest that protobuf syntax cannot capture.
func ValidateDeviceRegistrationRequest(request *pb.DeviceRegistrationRequest) error {
	if err := common_validators.ValidateDeviceId(request.DeviceRecord.Id); err != nil {
		return err
	}

	return common_validators.ValidateDeviceData(request.DeviceRecord.Data)
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

	return common_validators.ValidateDeviceId(response.DeviceId)
}
