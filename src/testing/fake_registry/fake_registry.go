// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package main is fake HTTP registry server. See README.md for more details.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"

	"google.golang.org/grpc/codes"
)

var (
	port                   = flag.Int("port", 9999, "Port to listen, defaults to 9999")
	registerDeviceURL      = flag.String("register_device_url", "/registerDevice", "URL to listen to RegisterDevice requests. Defaults to '/registerDevice'")
	batchRegisterDeviceURL = flag.String("batchRegister_device_url", "/batchRegisterDevice", "URL to listen to BatchRegisterDevice requests. Defaults to '/batchRegisterDevice'")
)

type callError struct {
	Code codes.Code `json:"code"`
}

type registerResponse struct {
	DeviceID string     `json:"deviceId"`
	Error    *callError `json:"error"`
}

type batchRegisterResponse struct {
	Responses []*registerResponse `json:"responses"`
}

var callErrorOK = callError{Code: codes.OK}

func handleError(w http.ResponseWriter, errorMessage string) {
	w.Write([]byte(errorMessage))
	w.WriteHeader(http.StatusBadRequest)
}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(w, "failed to read request body")
		return
	}
	req := &pbp.DeviceRegistrationRequest{}
	if err := json.Unmarshal(reqBytes, req); err != nil {
		handleError(w, "failed to unmarshal request body")
		return
	}
	resp := &registerResponse{
		DeviceID: req.GetRecord().GetDeviceId(),
		Error:    &callErrorOK,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		handleError(w, "failed to marshal response body")
		return
	}
	if _, err := w.Write(respBytes); err != nil {
		handleError(w, "failed to write response body")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func batchRegisterDevice(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		handleError(w, "failed to read request body")
		return
	}
	req := &pbp.BatchDeviceRegistrationRequest{}
	if err := json.Unmarshal(reqBytes, req); err != nil {
		handleError(w, "failed to unmarshal request body")
		return
	}
	resp := &batchRegisterResponse{Responses: make([]*registerResponse, 0)}
	for _, registerReq := range req.GetRequests() {
		resp.Responses = append(resp.Responses, &registerResponse{
			DeviceID: registerReq.GetRecord().GetDeviceId(),
			Error:    &callErrorOK,
		})
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		handleError(w, "failed to marshal response body")
		return
	}
	if _, err := w.Write(respBytes); err != nil {
		handleError(w, "failed to write response body")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func main() {
	flag.Parse()
	http.HandleFunc(*registerDeviceURL, registerDevice)
	http.HandleFunc(*batchRegisterDeviceURL, batchRegisterDevice)
	log.Printf("Listening on port %d...", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
