// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package registry_shim implements the ProvisioningAppliance:RegisterDevice RPC.
package registry_shim

import (
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	papb "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	proxybufferpb "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	proxybuffer "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	spmpb "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/grpconn"
)

var registryClient proxybuffer.Registry

func StartRegistryBuffer(registryBufferAddress string, enableTLS bool, caRootCerts string, serviceCert string, serviceKey string) error {
	opts := grpc.WithInsecure()
	if enableTLS {
		credentials, err := grpconn.LoadClientCredentials(caRootCerts, serviceCert, serviceKey)
		if err != nil {
			return err
		}
		opts = grpc.WithTransportCredentials(credentials)
	}

	conn, err := grpc.Dial(registryBufferAddress, opts, grpc.WithBlock())
	if err != nil {
		return err
	}
	registryClient = proxybufferpb.NewProxyBufferServiceClient(conn)
	return nil
}

func RegisterDevice(ctx context.Context, request *papb.RegistrationRequest, endorsement *spmpb.EndorseDataResponse) (*papb.RegistrationResponse, error) {
	log.Printf("In PA - Received RegisterDevice request with DeviceID: %v", diu.DeviceIdToHexString(request.DeviceData.DeviceId))

	// Vendor-specific implementation of RegisterDevice call goes here.
	return nil, status.Errorf(codes.Unimplemented, "Vendor specific RegisterDevice RPC not implemented.")
}
