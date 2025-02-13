// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the proxybuffer package.
package proxybuffer

import (
	"context"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/testing/protocmp"

	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db_fake"
)

const (
	// bufferConnectionSize is the size of the gRPC connection buffer.
	bufferConnectionSize = 2048 * 1024
)

func bufferDialer(t *testing.T, database *db.DB) func(context.Context, string) (net.Conn, error) {
	listener := bufconn.Listen(bufferConnectionSize)
	server := grpc.NewServer()
	pbp.RegisterProxyBufferServiceServer(server, proxybuffer.NewProxyBufferServer(database))
	go func(t *testing.T) {
		if err := server.Serve(listener); err != nil {
			t.Fatal(err)
		}
	}(t)
	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}

func TestRegisterDevice(t *testing.T) {
	ctx := context.Background()
	db_conn := db_fake.New()
	database := db.New(db_conn)
	conn, err := grpc.DialContext(ctx, "", grpc.WithInsecure(), grpc.WithContextDialer(bufferDialer(t, database)))
	if err != nil {
		t.Fatalf("failed to connect to test server: %v", err)
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
				Record: &dtd.RegistryRecordEmptyDeviceId,
			},
			expCode: codes.InvalidArgument,
			expDR:   nil,
		},
		{
			name: "empty sku",
			drr: &pbp.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordEmptySku,
			},
			expCode: codes.InvalidArgument,
			expDR:   nil,
		},
		{
			name: "empty data",
			drr: &pbp.DeviceRegistrationRequest{
				Record: &dtd.RegistryRecordEmptyData,
			},
			expCode: codes.InvalidArgument,
			expDR:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.RegisterDevice(ctx, tt.drr)
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
