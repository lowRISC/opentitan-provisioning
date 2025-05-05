// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package httpregistry creates an HTTP client that implements the Registry interface
package httpregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
)

type RegistryConfig struct {
	RegisterDeviceURL      string
	BatchRegisterDeviceURL string
	Headers                map[string]string
}

type Registry struct {
	RegistryConfig
	client *http.Client
}

// New creates a new HTTP registry that implements the proxybuffer.Registry interface
func New(config *RegistryConfig) (*Registry, error) {
	if _, err := url.Parse(config.RegisterDeviceURL); err != nil {
		return nil, fmt.Errorf("failed to parse config.RegisterDeviceURL: %v", err)
	}
	if _, err := url.Parse(config.BatchRegisterDeviceURL); err != nil {
		return nil, fmt.Errorf("failed to parse config.BatchRegisterDeviceURL: %v", err)
	}
	return &Registry{
		RegistryConfig: *config,
		client:         http.DefaultClient,
	}, nil
}

type callConfig struct {
	url        string
	headers    map[string]string
	httpClient *http.Client
}

// Types used for call

type callError struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type registerResponse struct {
	DeviceID string     `json:"deviceId"`
	Error    *callError `json:"error"`
}

type batchRegisterResponse struct {
	Responses []*registerResponse `json:"responses"`
}

// call is a generic wrapper around an HTTP call. It performs the following:
// 1. Marshal request body
// 2. Add request headers
// 3. Send POST request
// 4. Unmarshal response into a given pointer
//
// A response with a non-200 error code will be interpreted as success as long
// as the response body is a JSON.
func call[RequestMessage proto.Message, ResponseMessage any](ctx context.Context, config callConfig, req RequestMessage, resp ResponseMessage) error {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request into JSON: %v", err)
	}
	rawReq, err := http.NewRequestWithContext(ctx, http.MethodPost, config.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	for headerName, headerValue := range config.headers {
		rawReq.Header.Add(headerName, headerValue)
	}
	rawReq.Header.Add("Content-Type", "application/json")
	rawResp, err := config.httpClient.Do(rawReq)
	if err != nil {
		return fmt.Errorf("failed to execute HTTP request: %v", err)
	}
	respBody, err := ioutil.ReadAll(rawResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response body: %v", err)
	}
	if err := json.Unmarshal(respBody, resp); err != nil {
		return fmt.Errorf("failed to unmarshal response body: %v", err)
	}
	return nil
}

func serverResponseToPBResponse(resp *registerResponse) *pbp.DeviceRegistrationResponse {
	pbResp := &pbp.DeviceRegistrationResponse{
		DeviceId:  resp.DeviceID,
		Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
		RpcStatus: 0,
	}
	if resp.Error != nil {
		pbResp.RpcStatus = resp.Error.Code
		pbResp.Status = pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST
	}
	return pbResp
}

// RegisterDevice registers a device.
func (r *Registry) RegisterDevice(ctx context.Context, request *pbp.DeviceRegistrationRequest, _ ...grpc.CallOption) (*pbp.DeviceRegistrationResponse, error) {
	config := callConfig{
		url:        r.RegisterDeviceURL,
		headers:    r.Headers,
		httpClient: r.client,
	}
	response := &registerResponse{}
	err := call(ctx, config, request, response)
	if err != nil {
		return nil, err
	}
	pbResponse := serverResponseToPBResponse(response)
	pbResponse.DeviceId = request.Record.DeviceId
	return pbResponse, nil
}

// BatchRegisterDevice registers multiple devices.
func (r *Registry) BatchRegisterDevice(ctx context.Context, request *pbp.BatchDeviceRegistrationRequest, _ ...grpc.CallOption) (*pbp.BatchDeviceRegistrationResponse, error) {
	config := callConfig{
		url:        r.BatchRegisterDeviceURL,
		headers:    r.Headers,
		httpClient: r.client,
	}
	response := &batchRegisterResponse{}
	err := call(ctx, config, request, response)
	if err != nil {
		return nil, err
	}
	pbResponse := &pbp.BatchDeviceRegistrationResponse{
		Responses: make([]*pbp.DeviceRegistrationResponse, len(response.Responses)),
	}
	for i, resp := range response.Responses {
		pbResponse.Responses[i] = serverResponseToPBResponse(resp)
	}
	return pbResponse, nil
}
