// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
package validators

import (
	"testing"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
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
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &dtd.DeviceIdOk,
					Data: &dtd.DeviceDataOk,
				},
			},
			ok: true,
		},
		{
			name: "bad silicon creator id",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &dtd.DeviceIdBadSiliconCreatorId,
					Data: &dtd.DeviceDataOk,
				},
			},
		},
		{
			name: "bad product id",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &dtd.DeviceIdBadProductId,
					Data: &dtd.DeviceDataOk,
				},
			},
		},
		{
			name: "bad device data",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &dtd.DeviceIdOk,
					Data: &dtd.DeviceDataBadPayloadTooLarge,
				},
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
				DeviceId: &dtd.DeviceIdOk,
			},
			ok: true,
		},
		{
			name: "bad request",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
				DeviceId: &dtd.DeviceIdOk,
			},
			ok: true,
		},
		{
			name: "buffer full",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BUFFER_FULL,
				DeviceId: &dtd.DeviceIdOk,
			},
			ok: true,
		},
		{
			name: "invalid status",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus(-1),
				DeviceId: &dtd.DeviceIdOk,
			},
		},
		{
			name: "bad device id",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				DeviceId: &dtd.DeviceIdBadSiliconCreatorId,
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
