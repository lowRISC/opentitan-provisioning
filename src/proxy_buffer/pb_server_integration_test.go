// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the proxybuffer package.
package proxybuffer

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
)

func TestRegisterDevice(t *testing.T) {
	addr := os.Getenv("TEST_PROXY_SERVER_ADDRESS")
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to connect to test server: %q, error: %v", addr, err)
	}
	defer conn.Close()

	client := pbp.NewProxyBufferServiceClient(conn)

	tests := []struct {
		name    string
		drr     *pbp.DeviceRegistrationRequest
		expCode codes.Code
		expDR   *pbp.DeviceRegistrationResponse
	}{
		{
			name: "ok",
			drr: &pbp.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordOk,
			},
			expCode: codes.OK,
			expDR: &pbp.DeviceRegistrationResponse{
				Status:   pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				DeviceId: dtd.RegistryRecordOk.DeviceId},
		},
		{
			name: "empty device id",
			drr: &pbp.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordOk,
			},
			expCode: codes.InvalidArgument,
			expDR: &pbp.DeviceRegistrationResponse{
				Status:   pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
				DeviceId: dtd.RegistryRecordOk.DeviceId},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.RegisterDevice(context.Background(), tt.drr)
			s, ok := status.FromError(err)
			if !ok {
				t.Fatal("unable to extract status code from error")
			}
			if s.Code() != tt.expCode {
				t.Errorf("expected status code: %v, got %v", tt.expCode, s.Code())
			}
			if got != nil {
				if diff := cmp.Diff(tt.expDR, got, protocmp.Transform()); diff != "" {
					t.Errorf("RegisterDevice() returned unexpected diff (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("TEST_INTEGRATION_EN") != "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
