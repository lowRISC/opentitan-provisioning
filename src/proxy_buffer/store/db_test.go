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
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/db_fake"
)

func TestInsert(t *testing.T) {
	database := db.New(db_fake.New())
	record := &dtd.RegistryRecordOk

	if err := database.InsertDevice(context.Background(), record); err != nil {
		t.Fatalf("failed to insert record: %v", err)
	}

	got, err := database.GetDevice(context.Background(), record.DeviceId)
	if err != nil {
		t.Fatalf("failed to get record: %v", err)
	}

	if diff := cmp.Diff(record, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetDevice() returned unexpected diff (-want +got):\n%s", diff)
	}
}
