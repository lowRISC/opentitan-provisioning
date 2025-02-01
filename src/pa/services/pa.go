// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package pa implements the gRPC ProvisioningAppliance server interface.
package pa

import (
	"context"
	"fmt"
	"log"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pbp "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	pbr "github.com/lowRISC/opentitan-provisioning/src/registry_buffer/proto/registry_buffer_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service"
)

// server is the server object.
type server struct {
	// SPM gRPC client.
	spmClient pbs.SpmServiceClient

	// RegistryBuffer gRPC client.
	rbClient pbr.RegistryBufferServiceClient

	// Set to true to enable registry buffer. When set to false, the PA
	// will not nonnect to the registry buffer.
	enableRegBuff bool

	// muSKU is a mutex use to arbitrate SKU initialization access.
	muSKU sync.RWMutex
}

// NewProvisioningApplianceServer returns an implementation of the
// ProvisioningAppliance gRPC server.
func NewProvisioningApplianceServer(spmClient pbs.SpmServiceClient, rbClient pbr.RegistryBufferServiceClient, enableRegBuff bool) pbp.ProvisioningApplianceServiceServer {
	return &server{
		spmClient:     spmClient,
		rbClient:      rbClient,
		enableRegBuff: enableRegBuff,
	}
}

// InitSession sends a SKU initialization request to the SPM and returns a
// session token and associated PA endpoint.
func (s *server) InitSession(ctx context.Context, request *pbp.InitSessionRequest) (*pbp.InitSessionResponse, error) {
	// Generate a session token with the SPM.
	r, err := s.spmClient.InitSession(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}

	// Get authorization controller for the PA.
	auth_controller, err := auth_service.GetInstance()
	if err != nil {
		log.Printf("internal error, try to reset pa server")
		return nil, err
	}

	// Get context metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("metadata is not provided")
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	// Get userID and set session token.
	userID := auth_service.GetUserID(ctx, md)
	log.Printf("In PA InitSession: Add User: name = %s, token = %s, sku = %s", userID, r.SkuSessionToken, request.Sku)
	_, err = auth_controller.AddUser(userID, r.SkuSessionToken, request.Sku, r.AuthMethods)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add user: %v", err)
	}

	r.PaEndpoint = "TODO: SET_PA_ENDPOINT"

	return r, nil
}

// CloseSession sends a SKU initialization request to the SPM and returns a
// session token and associated PA endpoint.
func (s *server) CloseSession(ctx context.Context, request *pbp.CloseSessionRequest) (*pbp.CloseSessionResponse, error) {
	log.Printf("In PA CloseSession")

	// Get authorization controller for the PA.
	auth_controller, err := auth_service.GetInstance()
	if err != nil {
		log.Printf("internal error, try to reset pa server")
		return nil, err
	}

	// Get context metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("metadata is not provided")
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	// Get userID and close session.
	userID := auth_service.GetUserID(ctx, md)
	user, err := auth_controller.RemoveUser(userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove user: %v", err)
	}
	fmt.Println("Remove User: ", user)

	return &pbp.CloseSessionResponse{}, nil
}

// CreateKeyAndCert generates a set of wrapped keys, returns them and their endorsement certificates.
func (s *server) CreateKeyAndCert(ctx context.Context, request *pbp.CreateKeyAndCertRequest) (*pbp.CreateKeyAndCertResponse, error) {
	log.Printf("In PA - Received CreateKeyAndCert request with Sku=%s", request.Sku)

	// Call the service method, wait for server response.
	r, err := s.spmClient.CreateKeyAndCert(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// EndorseCerts endorses a set of TBS certificates and returns them.
func (s *server) EndorseCerts(ctx context.Context, request *pbp.EndorseCertsRequest) (*pbp.EndorseCertsResponse, error) {
	log.Printf("In PA - Received EndorseCerts request with Sku=%s", request.Sku)

	r, err := s.spmClient.EndorseCerts(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// DeriveSymmetricKeys generates a symmetric key from a seed (pre-provisioned in
// the SPM/HSM) and diversifier string.
func (s *server) DeriveSymmetricKeys(ctx context.Context, request *pbp.DeriveSymmetricKeysRequest) (*pbp.DeriveSymmetricKeysResponse, error) {
	log.Printf("In PA - Received DeriveSymmetricKeys request")
	r, err := s.spmClient.DeriveSymmetricKeys(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// SendDeviceRegistrationPayload registers a new device record to the local MySql DB.
func (s *server) SendDeviceRegistrationPayload(ctx context.Context, request *pbp.RegistrationRequest) (*pbp.RegistrationResponse, error) {
	log.Printf("In PA - Received SendDeviceRegistrationPayload request with DeviceID: %v", request.DeviceRecord.Id)

	if !s.enableRegBuff {
		return nil, status.Errorf(codes.Internal, "RegisterDevice ended with error, PA started without registry buffer")
	}

	// Call the service method, wait for server response.
	r, err := s.rbClient.RegisterDevice(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RegisterDevice returned error: %v", err)
	}
	return r, nil
}
