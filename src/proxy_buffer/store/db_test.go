// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package db_tests implements unit tests for the db package.
package db_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	dtd "github.com/lowRISC/opentitan-provisioning/src/proto/device_testdata"
	rpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db_fake"
)

func TestInsertAndGet(t *testing.T) {
	ctx := context.Background()
	database := db.New(db_fake.New())
	record := &dtd.RegistryRecordOk

	if err := database.InsertDevice(ctx, record); err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	got, err := database.GetDevice(ctx, record.DeviceId)
	if err != nil {
		t.Fatalf("failed to get record: %v", err)
	}

	if diff := cmp.Diff(record, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetDevice() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestInsertAndSync(t *testing.T) {
	ctx := context.Background()
	database := db.New(db_fake.New())
	record := &dtd.RegistryRecordOk

	if err := database.InsertDevice(ctx, record); err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	got, err := database.GetUnsyncedDevices(ctx, 1)
	if err != nil {
		t.Fatalf("failed to read unsynced devices: %v", err)
	}
	want := []*rpb.RegistryRecord{record}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetUnsyncedDevices() (before sync) returned unexpected diff (-want +got):\n%s", diff)
	}

	if err := database.MarkDevicesAsSynced(ctx, []string{record.DeviceId}); err != nil {
		t.Errorf("MarkDevicesAsSynced() returned unexpected error: %v", err)
	}

	got, err = database.GetUnsyncedDevices(ctx, 1)
	if err != nil {
		t.Fatalf("failed to read unsynced devices: %v", err)
	}
	want = []*rpb.RegistryRecord{}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetUnsyncedDevices() (after sync) returned unexpected diff (-want +got):\n%s", diff)
	}
}
