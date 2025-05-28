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
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/services/proxybuffer"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
)

// Options contains configuration options for a syncer to use
type Options struct {
	// How frequently the syncer runs. It should be a Go duration string
	// (see https://pkg.go.dev/time#ParseDuration).
	Frequency string
	// Number of records to process on each run.
	RecordsPerRun int
	// Number of times a record can be retried before it is considered a fatal
	// fail (which kills ProxyBuffer process). If less than 0, it will have
	// unlimited retries.
	MaxRetriesPerRecord int
}

// DefaultOptions returns the default options for a syncer
func DefaultOptions() *Options {
	return &Options{
		Frequency:           "10m",
		RecordsPerRun:       100,
		MaxRetriesPerRecord: 5,
	}
}

type syncer struct {
	db                  *db.DB
	registry            proxybuffer.Registry
	ticker              <-chan time.Time
	recordsPerRun       int
	maxRetriesPerRecord int
	retryCounter        map[string]int
	closeCh             chan struct{}
	fatalErrorsCh       chan error
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
		db:                  db,
		registry:            registry,
		ticker:              time.Tick(freq),
		recordsPerRun:       options.RecordsPerRun,
		maxRetriesPerRecord: options.MaxRetriesPerRecord,
		retryCounter:        make(map[string]int),
		closeCh:             make(chan struct{}, 1),
		fatalErrorsCh:       make(chan error, 1),
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
	fatalFailures := make([]string, 0)
	for _, response := range batchResponse.Responses {
		if response.Status == pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS {
			successfulDeviceIDs = append(successfulDeviceIDs, response.DeviceId)
			delete(s.retryCounter, response.DeviceId)
		} else {
			// If not in the map, it will be zero by default
			retryCount := s.retryCounter[response.DeviceId] + 1
			s.retryCounter[response.DeviceId] = retryCount
			errorMsg := fmt.Sprintf("id: %q, num_retries: %d, status: %s, rpc_status: %s",
				response.DeviceId,
				retryCount,
				pbp.DeviceRegistrationStatus_name[int32(response.Status)],
				codes.Code(response.RpcStatus),
			)
			if s.maxRetriesPerRecord >= 0 && retryCount >= s.maxRetriesPerRecord {
				// We wait until we finish processing all records to avoid
				// a state where a record is registered in the registry but not
				// marked as such in our database.
				fatalFailures = append(fatalFailures, errorMsg)
			}
			log.Printf("Request failed: %s", errorMsg)
		}
	}
	// We ensure to sync successful devices before sending fatal failures
	err = s.db.MarkDevicesAsSynced(ctx, successfulDeviceIDs)
	if len(fatalFailures) > 0 {
		// log.Fatal("before adding to channel")
		s.fatalErrorsCh <- fmt.Errorf("devices failed after retry limit: [%s]", strings.Join(fatalFailures, "; "))
	}
	return err
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

// FatalErrors returns a read-only channel to which fatal errors will be posted.
// A fatal error will happen in the following scenarios:
//
// - A device was retried `MaxRetriesPerRecord` times and failed again.
func (s *syncer) FatalErrors() <-chan error {
	return s.fatalErrorsCh
}
