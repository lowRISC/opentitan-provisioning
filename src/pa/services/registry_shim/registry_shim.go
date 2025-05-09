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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	papb "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	certpb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	commonpb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	ecdsapb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	diu "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_utils"
	rrpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
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

func RegisterDevice(ctx context.Context, spmClient spmpb.SpmServiceClient, request *papb.RegistrationRequest) (*papb.RegistrationResponse, error) {
	log.Printf("In PA - Received RegisterDevice request with DeviceID: %v", diu.DeviceIdToHexString(request.DeviceData.DeviceId))

	// Check if ProxyBuffer client (i.e., ProxyBuffer) is valid.
	if registryClient == nil {
		return nil, status.Errorf(codes.Internal, "RegisterDevice ended with error, PA started without ProxyBuffer")
	}

	// Extract ot.DeviceData to a raw byte buffer.
	deviceDataBytes, err := proto.Marshal(request.DeviceData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device data: %v", err)
	}

	// Endorse data payload.
	edRequest := &spmpb.EndorseDataRequest{
		Sku: request.DeviceData.Sku,
		KeyParams: &certpb.SigningKeyParams{
			KeyLabel: "SigningKey/Identity/v0",
			Key: &certpb.SigningKeyParams_EcdsaParams{
				EcdsaParams: &ecdsapb.EcdsaParams{
					HashType: commonpb.HashType_HASH_TYPE_SHA384,
					Curve:    commonpb.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P384,
					Encoding: ecdsapb.EcdsaSignatureEncoding_ECDSA_SIGNATURE_ENCODING_DER,
				},
			},
		},
		Data: deviceDataBytes,
	}
	edResponse, err := spmClient.EndorseData(ctx, edRequest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM-EndorseData returned error: %v", err)
	}

	// Translate/embed ot.DeviceData to the registry request.
	pbRequest := &proxybufferpb.DeviceRegistrationRequest{
		Record: &rrpb.RegistryRecord{
			DeviceId:      diu.DeviceIdToHexString(request.DeviceData.DeviceId),
			Sku:           request.DeviceData.Sku,
			Version:       0,
			Data:          deviceDataBytes,
			AuthPubkey:    edResponse.Pubkey,
			AuthSignature: edResponse.Signature,
		},
	}

	// Send record to the ProxyBuffer (the buffering front end of the registry service).
	pbResponse, err := registryClient.RegisterDevice(ctx, pbRequest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RegisterDevice returned error: %v", err)
	}
	log.Printf("In PA - device record (DeviceID: %v) accepted by ProxyBuffer: %v",
		pbResponse.DeviceId,
		pbResponse.Status)

	return &papb.RegistrationResponse{}, nil
}
