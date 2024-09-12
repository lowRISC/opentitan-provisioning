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
	// DeviceId objects.
	deviceIdOk = dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_OPENSOURCE,
			ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
			DeviceIdentificationNumber: 0,
		},
		SkuSpecific: make([]byte, common_validators.DeviceIdSkuSpecificLen),
	}
	deviceIdBadSiliconCreatorId = dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_UNSPECIFIED,
			ProductId:                  dpb.ProductId_PRODUCT_ID_EARLGREY_Z1,
			DeviceIdentificationNumber: 0,
		},
		SkuSpecific: make([]byte, common_validators.DeviceIdSkuSpecificLen),
	}
	deviceIdBadProductId = dpb.DeviceId{
		HardwareOrigin: &dpb.HardwareOrigin{
			SiliconCreatorId:           dpb.SiliconCreatorId_SILICON_CREATOR_ID_NUVOTON,
			ProductId:                  dpb.ProductId_PRODUCT_ID_UNSPECIFIED,
			DeviceIdentificationNumber: 0,
		},
		SkuSpecific: make([]byte, common_validators.DeviceIdSkuSpecificLen),
	}

	// DeviceData objects.
	deviceDataOk = dpb.DeviceData{
		Payload:         make([]byte, common_validators.MaxDeviceDataPayloadLen),
		DeviceLifeCycle: dpb.DeviceLifeCycle_DEVICE_LIFE_CYCLE_PROD,
	}
	deviceDataBadPayload = dpb.DeviceData{
		Payload:         make([]byte, common_validators.MaxDeviceDataPayloadLen+1),
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
			name: "bad silicon creator id",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &deviceIdBadSiliconCreatorId,
					Data: &deviceDataOk,
				},
			},
		},
		{
			name: "bad product id",
			drr: &pb.DeviceRegistrationRequest{
				DeviceRecord: &dpb.DeviceRecord{
					Id:   &deviceIdBadProductId,
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
				DeviceId: &deviceIdBadSiliconCreatorId,
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
