// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package registry_shim implements the ProvisioningAppliance:RegisterDevice RPC.
package registry_shim

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pap "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
)

func RegisterDevice(ctx context.Context, buffer pb.Registry, request *pap.RegistrationRequest) (*pap.RegistrationResponse, error) {
	log.Printf("In PA - Received RegisterDevice request with DeviceID: %v", diu.DeviceIdToHexString(request.DeviceData.DeviceId))

	// Vendor-specific implementation of RegisterDevice call goes here.
	return nil, status.Errorf(codes.Unimplemented, "Vendor specific RegisterDevice RPC not implemented.")
}
