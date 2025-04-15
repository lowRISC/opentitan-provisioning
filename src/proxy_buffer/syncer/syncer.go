// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package syncer implements a job to sync data from local store to a remote
// registry
package syncer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc/codes"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
)

// Options contains configuration options for a syncer to use
type Options struct {
	Frequency     string
	RecordsPerRun int
}

// DefaultOptions returns the default options for a syncer
func DefaultOptions() *Options {
	return &Options{
		Frequency:     "10m",
		RecordsPerRun: 100,
	}
}

type syncer struct {
	db            *db.DB
	registry      proxybuffer.Registry
	ticker        <-chan time.Time
	recordsPerRun int
	closeCh       chan struct{}
}

// New creates a new syncer that consumes a given db and publishes to a registry
func New(db *db.DB, registry proxybuffer.Registry, options *Options) (*syncer, error) {
	freq, err := time.ParseDuration(options.Frequency)
	if err != nil {
		return nil, fmt.Errorf("failed to parse options.Frequency: %v", err)
	}
	if options.RecordsPerRun <= 0 {
		return nil, errors.New("options.RecordsPerRun must be at least 1")
	}
	return &syncer{
		db:            db,
		registry:      registry,
		ticker:        time.Tick(freq),
		recordsPerRun: options.RecordsPerRun,
		closeCh:       make(chan struct{}),
	}, nil
}

func (s *syncer) run() error {
	ctx := context.Background()
	records, err := s.db.GetUnsyncedDevices(ctx, s.recordsPerRun)
	if err != nil {
		return err
	}
	batchRequest := &pbp.BatchDeviceRegistrationRequest{
		Requests: make([]*pbp.DeviceRegistrationRequest, len(records)),
	}
	for i, record := range records {
		batchRequest.Requests[i] = &pbp.DeviceRegistrationRequest{
			Record: record,
		}
	}
	batchResponse, err := s.registry.BatchRegisterDevice(ctx, batchRequest)
	if err != nil {
		return err
	}
	successfulDeviceIDs := make([]string, 0)
	for _, response := range batchResponse.Responses {
		if response.Status == pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS {
			successfulDeviceIDs = append(successfulDeviceIDs, response.DeviceId)
		} else {
			log.Printf(
				"Request with ID %q failed: status: %s, rpc_status: %s",
				response.DeviceId,
				pbp.DeviceRegistrationStatus_name[int32(response.Status)],
				codes.Code(response.RpcStatus),
			)
		}
	}
	return s.db.MarkDevicesAsSynced(ctx, successfulDeviceIDs)
}

func (s *syncer) listen() {
	for {
		select {
		case <-s.ticker:
			if err := s.run(); err != nil {
				log.Printf("run() failed: %v", err)
			}
		case <-s.closeCh:
			return
		}
	}
}

// Start starts the syncer
func (s *syncer) Start() {
	go s.listen()
}

// Stop stops the syncer
func (s *syncer) Stop() {
	s.closeCh <- struct{}{}
}
