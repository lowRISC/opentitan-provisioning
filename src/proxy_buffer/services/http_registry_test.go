// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package httpregistry_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

const (
	customHeaderName  = "X-My-Custom-Header"
	customHeaderValue = "mycustomheadervalue"
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

func registerDeviceSuccessWithHeader(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(customHeaderName) != customHeaderValue {
		registerDeviceError(w, r)
		return
	}
	registerDeviceSuccess(w, r)
}

func batchRegisterDeviceSuccess(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(batchRegisterDeviceSuccessBody))
}

func batchRegisterDeviceError(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("Internal server error"))
}

func batchRegisterDeviceSuccessWithHeader(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(customHeaderName) != customHeaderValue {
		batchRegisterDeviceError(w, r)
		return
	}
	batchRegisterDeviceSuccess(w, r)
}

func createHeadersFile(t *testing.T) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "headers.txt")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create temp headers file: %v", err)
	}
	file.Write([]byte(fmt.Sprintf("%s: %s\n", customHeaderName, customHeaderValue)))
	file.Close()
	return filename
}

func TestHTTPRegistryRegisterDevice(t *testing.T) {
	tcs := []struct {
		Name               string
		RegistryHandler    http.HandlerFunc
		IncludeHeadersFile bool
		Request            *pbp.DeviceRegistrationRequest
		ExpectedResponse   *pbp.DeviceRegistrationResponse
		ExpectAnError      bool
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
		{
			Name:               "SuccessWithHeaders",
			RegistryHandler:    registerDeviceSuccessWithHeader,
			IncludeHeadersFile: true,
			Request:            &deviceRegistrationRequest,
			ExpectedResponse:   &deviceRegistrationResponseSuccess,
		},
		{
			Name:               "FailureWithoutHeaders",
			RegistryHandler:    registerDeviceSuccessWithHeader,
			IncludeHeadersFile: false,
			Request:            &deviceRegistrationRequest,
			ExpectAnError:      true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			server := httptest.NewServer(tc.RegistryHandler)
			defer server.Close()
			registryConfig := &httpregistry.RegistryConfig{
				RegisterDeviceURL:      server.URL,
				BatchRegisterDeviceURL: server.URL,
			}
			if tc.IncludeHeadersFile {
				registryConfig.HeadersFilepath = createHeadersFile(t)
			}
			r, err := httpregistry.New(registryConfig)
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
		Name                 string
		BatchRegistryHandler http.HandlerFunc
		IncludeHeadersFile   bool
		Request              *pbp.BatchDeviceRegistrationRequest
		ExpectedResponse     *pbp.BatchDeviceRegistrationResponse
		ExpectAnError        bool
	}{
		{
			Name:                 "Success",
			BatchRegistryHandler: batchRegisterDeviceSuccess,
			Request:              &batchDeviceRegistrationRequest,
			ExpectedResponse:     &batchDeviceRegistrationResponseSuccess,
		},
		{
			Name:                 "Error",
			BatchRegistryHandler: batchRegisterDeviceError,
			Request:              &batchDeviceRegistrationRequest,
			ExpectAnError:        true,
		},
		{
			Name:                 "SuccessWithHeaders",
			BatchRegistryHandler: batchRegisterDeviceSuccessWithHeader,
			IncludeHeadersFile:   true,
			Request:              &batchDeviceRegistrationRequest,
			ExpectedResponse:     &batchDeviceRegistrationResponseSuccess,
		},
		{
			Name:                 "FailureWithoutHeaders",
			BatchRegistryHandler: batchRegisterDeviceSuccessWithHeader,
			IncludeHeadersFile:   false,
			Request:              &batchDeviceRegistrationRequest,
			ExpectAnError:        true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			server := httptest.NewServer(tc.BatchRegistryHandler)
			defer server.Close()
			registryConfig := &httpregistry.RegistryConfig{
				RegisterDeviceURL:      server.URL,
				BatchRegisterDeviceURL: server.URL,
			}
			if tc.IncludeHeadersFile {
				registryConfig.HeadersFilepath = createHeadersFile(t)
			}
			r, err := httpregistry.New(registryConfig)
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

const (
	validHeadersContent            = "Authorization: Bearer TOKEN\n"
	validConfigJSONContentTemplate = `{
  "register_device_url": "http://localhost:8080/register",
  "batch_register_device_url": "http://localhost:8080/batch_register",
  "headers_filepath": "%s"
}`
	filePermissions = 0644
)

func TestNewFromJSON(t *testing.T) {
	tcs := []struct {
		Name          string
		CreateFile    func(t *testing.T) string
		ExpectAnError bool
	}{
		{
			Name: "ValidConfig",
			CreateFile: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				headersFile := filepath.Join(dir, "headers.txt")
				if err := os.WriteFile(headersFile, []byte(validHeadersContent), filePermissions); err != nil {
					t.Fatalf("Unexpected error when writing headers file: %v", err)
				}
				configFile := filepath.Join(dir, "config.json")
				if err := os.WriteFile(configFile, []byte(fmt.Sprintf(validConfigJSONContentTemplate, headersFile)), filePermissions); err != nil {
					t.Fatalf("Unexpected error when writing config file: %v", err)
				}
				return configFile
			},
		},
		{
			Name: "ValidConfigNoHeadersFile",
			CreateFile: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				configFile := filepath.Join(dir, "config.json")
				if err := os.WriteFile(configFile, []byte(fmt.Sprintf(validConfigJSONContentTemplate, "")), filePermissions); err != nil {
					t.Fatalf("Unexpected error when writing config file: %v", err)
				}
				return configFile
			},
		},
		{
			Name: "EmptyConfigName",
			CreateFile: func(t *testing.T) string {
				return ""
			},
			ExpectAnError: true,
		},
		{
			Name: "InvalidConfig",
			CreateFile: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				configFile := filepath.Join(dir, "config.json")
				if err := os.WriteFile(configFile, []byte("garbage config"), filePermissions); err != nil {
					t.Fatalf("Unexpected error when writing config file: %v", err)
				}
				return configFile
			},
			ExpectAnError: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.CreateFile == nil {
				t.Fatal("CreateFile function is nil, it should not be")
			}
			filepath := tc.CreateFile(t)
			_, err := httpregistry.NewFromJSON(filepath)
			if err != nil && !tc.ExpectAnError {
				t.Errorf("Expected no error, got %v", err)
				return
			}
			if err == nil && tc.ExpectAnError {
				t.Error("Expected an error, got nil")
				return
			}
		})
	}
}
