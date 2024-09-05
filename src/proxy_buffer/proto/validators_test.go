// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
package validators

import (
	"testing"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	common_validators "github.com/lowRISC/opentitan-provisioning/src/proto/validators"
	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

var (
	deviceIdOk = dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			DeviceType: &dpb.DeviceType{
				SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_TEST,
				ProductIdentifier: 0,
			},
			DeviceIdentificationNumber: 0,
		},
		SkuSpecific: make([]byte, common_validators.DeviceIdSkuSpecificLen),
	}
	deviceIdBadCreator = dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			DeviceType: &dpb.DeviceType{
				SiliconCreator:    dpb.SiliconCreator_SILICON_CREATOR_UNSPECIFIED,
				ProductIdentifier: 0,
			},
			DeviceIdentificationNumber: 0,
		},
		SkuSpecific: make([]byte, common_validators.DeviceIdSkuSpecificLen),
	}

	deviceDataOk = dpb.DeviceData{
		DeviceIdPubs:    nil,
		Payload:         make([]byte, common_validators.MinDeviceDataPayloadLen),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
	}
	deviceDataBadPayload = dpb.DeviceData{
		DeviceIdPubs:    nil,
		Payload:         make([]byte, common_validators.MinDeviceDataPayloadLen-1),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
	}
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
					Id:   &deviceIdOk,
					Data: &deviceDataOk,
				},
			},
			ok: true,
		},
		{
			name: "bad id",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &deviceIdBadCreator,
					Data: &deviceDataOk,
				},
			},
		},
		{
			name: "bad device data",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &deviceIdOk,
					Data: &deviceDataBadPayload,
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
				DeviceId: &deviceIdOk,
			},
			ok: true,
		},
		{
			name: "bad request",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
				DeviceId: &deviceIdOk,
			},
			ok: true,
		},
		{
			name: "buffer full",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BUFFER_FULL,
				DeviceId: &deviceIdOk,
			},
			ok: true,
		},
		{
			name: "invalid status",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus(-1),
				DeviceId: &deviceIdOk,
			},
		},
		{
			name: "bad device id",
			drr: &pb.DeviceRegistrationResponse{
				Status:   pb.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				DeviceId: &deviceIdBadCreator,
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
