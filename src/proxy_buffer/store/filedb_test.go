// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package filedb_test implements unit tests for the filedb package.
package filedb_test

import (
	"context"
	"testing"

	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/connector"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/filedb"
)

func newDB(t *testing.T) connector.Connector {
	c, err := filedb.New("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	return c
}

func TestInsert(t *testing.T) {
	db := newDB(t)
	if err := db.Insert(context.Background(), "key", []byte("value")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
}

func TestGet(t *testing.T) {
	db := newDB(t)
	if err := db.Insert(context.Background(), "key", []byte("value")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}

	value, err := db.Get(context.Background(), "key")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	if string(value) != "value" {
		t.Errorf("Get returned wrong value: got %q, want %q", value, "value")
	}
}
