// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package pa implements the gRPC ProvisioningAppliance server interface.
package pa

import (
	"context"
	"log"
	"sync"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pap "github.com/lowRISC/opentitan-provisioning/src/pa/proto/pa_go_pb"
	rs "github.com/lowRISC/opentitan-provisioning/src/pa/services/registry_shim"
	certpb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/cert_go_pb"
	commonpb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/common_go_pb"
	ecdsapb "github.com/lowRISC/opentitan-provisioning/src/proto/crypto/ecdsa_go_pb"
	pbs "github.com/lowRISC/opentitan-provisioning/src/spm/proto/spm_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/transport/auth_service"
)

// server is the server object.
type server struct {
	// SPM gRPC client.
	spmClient pbs.SpmServiceClient

	// muSKU is a mutex use to arbitrate SKU initialization access.
	muSKU sync.RWMutex
}

// NewProvisioningApplianceServer returns an implementation of the
// ProvisioningAppliance gRPC server.
func NewProvisioningApplianceServer(spmClient pbs.SpmServiceClient) pap.ProvisioningApplianceServiceServer {
	return &server{
		spmClient: spmClient,
	}
}

// InitSession sends a SKU initialization request to the SPM and returns a
// session token and associated PA endpoint.
func (s *server) InitSession(ctx context.Context, request *pap.InitSessionRequest) (*pap.InitSessionResponse, error) {
	log.Printf("PA.InitSession SKU: %q", request.Sku)

	// Generate a session token with the SPM.
	r, err := s.spmClient.InitSession(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.InitSession returned error: %s", st.Message())
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
	log.Printf("InitSession: Add User: name: %s, token: %s, sku: %s", userID, r.SkuSessionToken, request.Sku)
	_, err = auth_controller.AddUser(userID, r.SkuSessionToken, request.Sku, r.AuthMethods)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add user: %v", err)
	}
	return r, nil
}

// CloseSession sends a SKU initialization request to the SPM and returns a
// session token and associated PA endpoint.
func (s *server) CloseSession(ctx context.Context, request *pap.CloseSessionRequest) (*pap.CloseSessionResponse, error) {
	log.Printf("PA.CloseSession")

	// Get authorization controller for the PA.
	auth_controller, err := auth_service.GetInstance()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get auth controller: %v", err)
	}

	// Get context metadata.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	// Get userID and close session.
	userID := auth_service.GetUserID(ctx, md)
	user, err := auth_controller.RemoveUser(userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove user %q: %v", userID, err)
	}
	log.Printf("Remove User: %q", user)

	return &pap.CloseSessionResponse{}, nil
}

// EndorseCerts endorses a set of TBS certificates and returns them.
func (s *server) EndorseCerts(ctx context.Context, request *pap.EndorseCertsRequest) (*pap.EndorseCertsResponse, error) {
	log.Printf("PA.EndorseCerts Sku: %q", request.Sku)

	r, err := s.spmClient.EndorseCerts(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.EndorseCerts returned error: %s", st.Message())
	}
	return r, nil
}

// DeriveTokens generates a symmetric key from a seed (pre-provisioned in
// the SPM/HSM) and diversifier string.
func (s *server) DeriveTokens(ctx context.Context, request *pap.DeriveTokensRequest) (*pap.DeriveTokensResponse, error) {
	log.Printf("PA.DeriveTokens Sku: %q", request.Sku)
	r, err := s.spmClient.DeriveTokens(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.DeriveTokens returned error: %s", st.Message())
	}
	return r, nil
}

// GetStoredTokens retrieves a token stored within the SPM.
func (s *server) GetStoredTokens(ctx context.Context, request *pap.GetStoredTokensRequest) (*pap.GetStoredTokensResponse, error) {
	log.Printf("PA.GetStoredTokens Sku: %q", request.Sku)
	r, err := s.spmClient.GetStoredTokens(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.GetStoredTokens returned error: %s", st.Message())
	}
	return r, nil
}

// GetCaSubjectKeys retrieves the CA serial numbers for a given SKU.
func (s *server) GetCaSubjectKeys(ctx context.Context, request *pap.GetCaSubjectKeysRequest) (*pap.GetCaSubjectKeysResponse, error) {
	log.Printf("PA.GetCaSubjectKeys Sku: %q", request.Sku)
	r, err := s.spmClient.GetCaSubjectKeys(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.GetCaSubjectKeys returned error: %s", st.Message())
	}
	return r, nil
}

// GetOwnerFwBootMessage retrieves the owner firmware boot message for a given SKU.
func (s *server) GetOwnerFwBootMessage(ctx context.Context, request *pap.GetOwnerFwBootMessageRequest) (*pap.GetOwnerFwBootMessageResponse, error) {
	log.Printf("PA.GetOwnerFwBootMessage Sku: %q", request.Sku)
	r, err := s.spmClient.GetOwnerFwBootMessage(ctx, request)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.GetOwnerFwBootMessage returned error: %s", st.Message())
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
	log.Printf("PA.RegisterDevice Sku: %q", request.DeviceData.Sku)

	// Extract ot.DeviceData to a raw byte buffer. 
	deviceDataBytes, err := proto.Marshal(request.DeviceData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to marshal device data: %v err: %v", err, request.DeviceData)
	}

	// Verify the device data.
	if _, err := s.spmClient.VerifyDeviceData(ctx, &pbs.VerifyDeviceDataRequest{
		DeviceData: request.DeviceData,
	}); err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.VerifyDeviceData returned error: %s", st.Message())
	}

	// Endorse data payload.
	edRequest := &pbs.EndorseDataRequest{
		Sku: request.DeviceData.Sku,
		KeyParams: &certpb.SigningKeyParams{
			KeyLabel: "SigningKey/Identity/v0",
			Key: &certpb.SigningKeyParams_EcdsaParams{
				EcdsaParams: &ecdsapb.EcdsaParams{
					HashType: commonpb.HashType_HASH_TYPE_SHA256,
					Curve:    commonpb.EllipticCurveType_ELLIPTIC_CURVE_TYPE_NIST_P256,
					Encoding: ecdsapb.EcdsaSignatureEncoding_ECDSA_SIGNATURE_ENCODING_DER,
				},
			},
		},
		Data: deviceDataBytes,
	}
	edResponse, err := s.spmClient.EndorseData(ctx, edRequest)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "SPM.EndorseData returned error: %s", st.Message())
	}

	return rs.RegisterDevice(ctx, request, edResponse)
}
