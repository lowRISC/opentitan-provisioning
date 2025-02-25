// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package registry_shim implements the ProvisioningAppliance:RegisterDevice RPC.
package registry_shim

import (
	"context"
	"fmt"
	"log"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pap "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	rpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	pbr "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	pb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
)

func RegisterDevice(ctx context.Context, buffer pb.Registry, request *pap.RegistrationRequest) (*pap.RegistrationResponse, error) {
	log.Printf("In PA - Received RegisterDevice request with DeviceID: %v", diu.DeviceIdToHexString(request.DeviceData.DeviceId))

	// Check if ProxyBuffer is enabled.
	if buffer == nil {
		return nil, status.Errorf(codes.Internal, "RegisterDevice ended with error, PA started without ProxyBuffer")
	}

	// Translate/embed ot.DeviceData to the registry request.
	device_data_bytes, err := proto.Marshal(request.DeviceData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device data: %v", err)
	}
	pb_request := &pbr.DeviceRegistrationRequest{
		Record: &rpb.RegistryRecord{
			DeviceId: diu.DeviceIdToHexString(request.DeviceData.DeviceId),
			Sku:      request.DeviceData.Sku,
			Version:  0,
			Data:     device_data_bytes,
		},
	}

	// Send record to the ProxyBuffer (the buffering front end of the registry service).
	pb_response, err := buffer.RegisterDevice(ctx, pb_request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RegisterDevice returned error: %v", err)
	}
	log.Printf("In PA - device record (DeviceID: %v) accepted by ProxyBuffer: %v",
		pb_response.DeviceId,
		pb_response.Status)

	return &pap.RegistrationResponse{}, nil
}
