// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
package validators

import (
	"testing"

	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

func TestValidateDeviceRegistrationRequest(t *testing.T) {
	tests := []struct {
		name string
		drr  *pb.DeviceRegistrationRequest
		ok   bool
	}{
		{
			name: "ok",
			drr: &pb.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordOk,
			},
			ok: true,
		},
		{
			name: "empty device id",
			drr: &pb.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordEmptyDeviceId,
			},
		},
		{
			name: "empty sku",
			drr: &pb.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordEmptySku,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceRegistrationRequest(tt.drr); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}

func TestValidateDeviceRegistrationResponse(t *testing.T) {
	tests := []struct {
		name string
		drr  *pb.DeviceRegistrationResponse
		ok   bool
	}{
		{
			name: "ok",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				DeviceId: diu.DeviceIdToHexString(&dtd.DeviceIdOk),
			},
			ok: true,
		},
		{
			name: "bad request",
			drr: &pb.DeviceRegistrationResponse{
				DeviceId: diu.DeviceIdToHexString(&dtd.DeviceIdOk),
			},
		},
		{
			name: "buffer full",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BUFFER_FULL,
				DeviceId: diu.DeviceIdToHexString(&dtd.DeviceIdOk),
			},
			ok: true,
		},
		{
			name: "invalid status",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus(-1),
				DeviceId: diu.DeviceIdToHexString(&dtd.DeviceIdOk),
			},
		},
		{
			name: "bad device id",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				DeviceId: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDeviceRegistrationResponse(tt.drr); (err == nil) != tt.ok {
				t.Errorf("expected ok=%t; got err=%q", tt.ok, err)
			}
		})
	}
}
