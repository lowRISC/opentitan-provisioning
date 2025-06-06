// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

package syncer_test

import (
	"context"
	"encoding/binary"
	"sort"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/google/go-cmp/cmp"

	testdata "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	rpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	pbp "github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/proto/proxy_buffer_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db_fake"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/syncer"
)

type fakeRegistry struct {
	successfulIDs []string
}

func (f *fakeRegistry) RegisterDevice(ctx context.Context, request *pbp.DeviceRegistrationRequest, opts ...grpc.CallOption) (*pbp.DeviceRegistrationResponse, error) {
	for _, successfulID := range f.successfulIDs {
		if request.Record.DeviceId == successfulID {
			return &pbp.DeviceRegistrationResponse{
				DeviceId:  request.Record.DeviceId,
				Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_SUCCESS,
				RpcStatus: uint32(codes.OK),
			}, nil
		}
	}
	return &pbp.DeviceRegistrationResponse{
		DeviceId:  request.Record.DeviceId,
		Status:    pbp.DeviceRegistrationStatus_DEVICE_REGISTRATION_STATUS_BAD_REQUEST,
		RpcStatus: uint32(codes.InvalidArgument),
	}, status.Errorf(codes.InvalidArgument, "fake failure for deviceID %s", request.Record.DeviceId)
}

func (f *fakeRegistry) BatchRegisterDevice(ctx context.Context, request *pbp.BatchDeviceRegistrationRequest, opts ...grpc.CallOption) (*pbp.BatchDeviceRegistrationResponse, error) {
	response := &pbp.BatchDeviceRegistrationResponse{
		Responses: make([]*pbp.DeviceRegistrationResponse, len(request.Requests)),
	}
	for i, req := range request.Requests {
		response.Responses[i], _ = f.RegisterDevice(ctx, req, opts...)
	}
	return response, nil
}

func registryRecord(idOffset int) *rpb.RegistryRecord {
	deviceID := &testdata.DeviceIdOk
	binary.BigEndian.PutUint32(deviceID.SkuSpecific[0:4], uint32(idOffset))
	record := testdata.NewRegistryRecordOk(deviceID)
	return &record
}

// sortRegistryRecords sorts a slice of RegistryRecord entries by their device ID
func sortRegistryRecords(records []*rpb.RegistryRecord) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].DeviceId < records[j].DeviceId
	})
}

func TestSyncer(t *testing.T) {
	ctx := context.Background()
	database := db.New(db_fake.New())
	allRecords := make([]*rpb.RegistryRecord, 5)
	for i := 0; i < 5; i++ {
		allRecords[i] = registryRecord(i)
		if err := database.InsertDevice(ctx, allRecords[i]); err != nil {
			t.Fatalf("unexpected error when registering record: %v", err)
		}
	}

	registry := &fakeRegistry{
		successfulIDs: []string{
			allRecords[0].DeviceId,
			allRecords[1].DeviceId,
			allRecords[2].DeviceId,
		},
	}
	options := &syncer.Options{
		Frequency:           "1s",
		RecordsPerRun:       5,
		MaxRetriesPerRecord: 2,
	}
	sync, err := syncer.New(database, registry, options)
	if err != nil {
		t.Fatalf("unexpected error when creating syncer: %v", err)
	}

	sync.Start()
	time.Sleep(time.Second * 3)
	sync.Stop()

	unsyncedRecords, err := database.GetUnsyncedDevices(ctx, 5)
	if err != nil {
		t.Fatalf("unexpected error when retrieving unsynced devices: %v", err)
	}
	expectedUnsyncedRecords := []*rpb.RegistryRecord{
		allRecords[3],
		allRecords[4],
	}

	// Sort both slices before comparison to ensure consistent ordering
	sortRegistryRecords(unsyncedRecords)
	sortRegistryRecords(expectedUnsyncedRecords)

	if diff := cmp.Diff(unsyncedRecords, expectedUnsyncedRecords, protocmp.Transform()); diff != "" {
		t.Errorf("unsynced records diffs (-got +want):\n%s", diff)
	}

	select {
	case <-sync.FatalErrors():
		break
	default:
		t.Errorf("expected error in FatalErrors() channel, got nothing")
	}
}
