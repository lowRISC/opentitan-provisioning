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

	"github.com/google/go-cmp/cmp"
)

func newDB(t *testing.T) connector.Connector {
	t.Helper()
	c, err := filedb.New("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	return c
}

func closeDB(t *testing.T, db connector.Connector) {
	t.Helper()
	if err := filedb.Close(db); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}
}

func TestInsert(t *testing.T) {
	db := newDB(t)
	defer closeDB(t, db)
	if err := db.Insert(context.Background(), "key", "sku", []byte("value")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
}

func TestGet(t *testing.T) {
	db := newDB(t)
	defer closeDB(t, db)
	ctx := context.Background()
	if err := db.Insert(ctx, "key", "sku", []byte("value")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}

	got, err := db.Get(ctx, "key")
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
	want := "value"
	if string(got) != want {
		t.Errorf("Get returned wrong value: got %q, want %q", string(got), want)
	}
}

func TestGetUnsynced(t *testing.T) {
	db := newDB(t)
	defer closeDB(t, db)
	ctx := context.Background()
	if err := db.Insert(ctx, "key1", "sku", []byte("value1")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	if err := db.Insert(ctx, "key2", "sku", []byte("value2")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	got, err := db.GetUnsynced(ctx, 5)
	if err != nil {
		t.Errorf("GetUnsynced failed: %v", err)
	}
	want := [][]byte{[]byte("value1"), []byte("value2")}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("GetUnsynced diff: (-got, +want)\n%s", diff)
	}
}

func TestMarkAsSynced(t *testing.T) {
	db := newDB(t)
	defer closeDB(t, db)
	ctx := context.Background()
	if err := db.Insert(ctx, "key1", "sku", []byte("value1")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	if err := db.Insert(ctx, "key2", "sku", []byte("value2")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	if err := db.Insert(ctx, "key3", "sku", []byte("value3")); err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	if err := db.MarkAsSynced(ctx, []string{"key1", "key3"}); err != nil {
		t.Errorf("MarkAsSynced failed: %v", err)
	}
	got, err := db.GetUnsynced(ctx, 5)
	if err != nil {
		t.Errorf("GetUnsynced failed: %v", err)
	}
	want := [][]byte{[]byte("value2")}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("GetUnsynced diff: (-got, +want)\n%s", diff)
	}
}
