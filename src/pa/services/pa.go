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

	pap "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	rs "github.com/lowRISC/opentitan-provisioning/src/pa/services/registry_shim"
	pbr "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service"
)

// server is the server object.
type server struct {
	// SPM gRPC client.
	spmClient pbs.SpmServiceClient

	// ProxyBuffer gRPC client.
	pbClient pbr.ProxyBufferServiceClient

	// muSKU is a mutex use to arbitrate SKU initialization access.
	muSKU sync.RWMutex
}

// NewProvisioningApplianceServer returns an implementation of the
// ProvisioningAppliance gRPC server.
func NewProvisioningApplianceServer(spmClient pbs.SpmServiceClient, pbClient pbr.ProxyBufferServiceClient) pap.ProvisioningApplianceServiceServer {
	return &server{
		spmClient: spmClient,
		pbClient:  pbClient,
	}
}

// InitSession sends a SKU initialization request to the SPM and returns a
// session token and associated PA endpoint.
func (s *server) InitSession(ctx context.Context, request *pap.InitSessionRequest) (*pap.InitSessionResponse, error) {
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
func (s *server) CloseSession(ctx context.Context, request *pap.CloseSessionRequest) (*pap.CloseSessionResponse, error) {
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

	return &pap.CloseSessionResponse{}, nil
}

// EndorseCerts endorses a set of TBS certificates and returns them.
func (s *server) EndorseCerts(ctx context.Context, request *pap.EndorseCertsRequest) (*pap.EndorseCertsResponse, error) {
	log.Printf("In PA - Received EndorseCerts request with Sku=%s", request.Sku)

	r, err := s.spmClient.EndorseCerts(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// DeriveTokens generates a symmetric key from a seed (pre-provisioned in
// the SPM/HSM) and diversifier string.
func (s *server) DeriveTokens(ctx context.Context, request *pap.DeriveTokensRequest) (*pap.DeriveTokensResponse, error) {
	log.Printf("In PA - Received DeriveTokens request")
	r, err := s.spmClient.DeriveTokens(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// GetStoredTokens retrieves a token stored within the SPM.
func (s *server) GetStoredTokens(ctx context.Context, request *pap.GetStoredTokensRequest) (*pap.GetStoredTokensResponse, error) {
	log.Printf("In PA - Received GetStoredTokens request")
	r, err := s.spmClient.GetStoredTokens(ctx, request)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SPM returned error: %v", err)
	}
	return r, nil
}

// RegisterDevice registers a new device record in the registry database.
//
// The registry database is accessed through the ProxyBuffer or any downstream
// integrator specific registry service. To enable downstream integrators to
// interface with their registry service(s), an overrideable shim layer is used
// to implement this RPC.
func (s *server) RegisterDevice(ctx context.Context, request *pap.RegistrationRequest) (*pap.RegistrationResponse, error) {
	return rs.RegisterDevice(ctx, s.spmClient, s.pbClient, request)
}
