// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package httpregistry_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/httpregistry"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	deviceRegistrationRequest = pbp.DeviceRegistrationRequest{
		Record: &dtd.RegistryRecordOk,
	}
	batchDeviceRegistrationRequest = pbp.BatchDeviceRegistrationRequest{
		Requests: []*pbp.DeviceRegistrationRequest{
			&deviceRegistrationRequest,
			&deviceRegistrationRequest,
		},
	}

	deviceRegistrationResponseSuccess = pbp.DeviceRegistrationResponse{
		Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
		DeviceId:  dtd.RegistryRecordOk.GetDeviceId(),
		RpcStatus: uint32(codes.OK),
	}
	deviceRegistrationResponseFailure = pbp.DeviceRegistrationResponse{
		Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
		DeviceId:  dtd.RegistryRecordOk.GetDeviceId(),
		RpcStatus: uint32(codes.InvalidArgument),
	}

	batchDeviceRegistrationResponseSuccess = pbp.BatchDeviceRegistrationResponse{
		Responses: []*pbp.DeviceRegistrationResponse{
			&deviceRegistrationResponseSuccess,
			&deviceRegistrationResponseFailure,
		},
	}
)

var (
	registerDeviceSuccessBody = fmt.Sprintf(`{
	"deviceId": "%s"
}`, dtd.RegistryRecordOk.DeviceId)

	registerDeviceFailureBody = `{
	"error": {
		"code": 3,
		"status": "INVALID_ARGUMENT",
		"message": "Fake error"
	}
}`

	batchRegisterDeviceSuccessBody = fmt.Sprintf(`{
	"responses": [
		{
			"deviceId": "%s"
		},
		{
			"deviceId": "%s",
			"error": {
				"code": 3,
				"status": "INVALID_ARGUMENT",
				"message": "Fake error"
			}
		}
	]
}`, dtd.RegistryRecordOk.DeviceId, dtd.RegistryRecordOk.DeviceId)
)

func registerDeviceSuccess(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(registerDeviceSuccessBody))
}

func registerDeviceFailure(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(registerDeviceFailureBody))
	w.WriteHeader(http.StatusBadRequest)
}

func registerDeviceError(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Internal server error"))
}

func batchRegisterDeviceSuccess(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(batchRegisterDeviceSuccessBody))
}

func batchRegisterDeviceError(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Internal server error"))
}

func TestHTTPRegistryRegisterDevice(t *testing.T) {
	tcs := []struct {
		Name             string
		RegistryHandler  http.HandlerFunc
		Request          *pbp.DeviceRegistrationRequest
		ExpectedResponse *pbp.DeviceRegistrationResponse
		ExpectAnError    bool
	}{
		{
			Name:             "Success",
			RegistryHandler:  registerDeviceSuccess,
			Request:          &deviceRegistrationRequest,
			ExpectedResponse: &deviceRegistrationResponseSuccess,
		},
		{
			Name:             "Failure",
			RegistryHandler:  registerDeviceFailure,
			Request:          &deviceRegistrationRequest,
			ExpectedResponse: &deviceRegistrationResponseFailure,
		},
		{
			Name:            "Error",
			RegistryHandler: registerDeviceError,
			Request:         &deviceRegistrationRequest,
			ExpectAnError:   true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			server := httptest.NewServer(tc.RegistryHandler)
			defer server.Close()
			r, err := httpregistry.New(&httpregistry.RegistryConfig{
				RegisterDeviceURL:      server.URL,
				BatchRegisterDeviceURL: server.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error when creating new HTTP registry: %v", err)
			}

			ctx := context.Background()
			response, err := r.RegisterDevice(ctx, tc.Request)
			if err != nil && !tc.ExpectAnError {
				t.Fatalf("RegisterDevice() returned unexpected error: %v", err)
			}
			if err == nil && tc.ExpectAnError {
				t.Fatal("RegisterDevice() expected an error, but returned none")
			}
			if err != nil && tc.ExpectAnError {
				// Expected error
				return
			}
			if diff := cmp.Diff(tc.ExpectedResponse, response, protocmp.Transform()); diff != "" {
				t.Errorf("RegisterDevice() diff: (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestHTTPRegistryBatchRegisterDevice(t *testing.T) {
	tcs := []struct {
		Name             string
		RegistryHandler  http.HandlerFunc
		Request          *pbp.BatchDeviceRegistrationRequest
		ExpectedResponse *pbp.BatchDeviceRegistrationResponse
		ExpectAnError    bool
	}{
		{
			Name:             "Success",
			RegistryHandler:  batchRegisterDeviceSuccess,
			Request:          &batchDeviceRegistrationRequest,
			ExpectedResponse: &batchDeviceRegistrationResponseSuccess,
		},
		{
			Name:            "Error",
			RegistryHandler: batchRegisterDeviceError,
			Request:         &batchDeviceRegistrationRequest,
			ExpectAnError:   true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			server := httptest.NewServer(tc.RegistryHandler)
			defer server.Close()
			r, err := httpregistry.New(&httpregistry.RegistryConfig{
				RegisterDeviceURL:      server.URL,
				BatchRegisterDeviceURL: server.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error when creating new HTTP registry: %v", err)
			}

			ctx := context.Background()
			response, err := r.BatchRegisterDevice(ctx, tc.Request)
			if err != nil && !tc.ExpectAnError {
				t.Fatalf("BatchRegisterDevice() returned unexpected error: %v", err)
			}
			if err == nil && tc.ExpectAnError {
				t.Fatal("BatchRegisterDevice() expected an error, but returned none")
			}
			if err != nil && tc.ExpectAnError {
				// Expected error
				return
			}
			if diff := cmp.Diff(tc.ExpectedResponse, response, protocmp.Transform()); diff != "" {
				t.Errorf("BatchRegisterDevice() diff: (-want, +got):\n%s", diff)
			}
		})
	}
}
