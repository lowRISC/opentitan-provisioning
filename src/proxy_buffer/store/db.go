// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package db implements a database interface for the proxy buffer service.
package db

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/proto"

	rpb "github.com/lowRISC/opentitan-provisioning/src/proto/registry_record_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/connector"
)

// DB implements the Proxy Buffer database abstraction layer.
type DB struct {
	// conn is the database connector interface.
	conn connector.Connector
}

// New creates a database `DB` instance with a given `c` databace connection.
func New(c connector.Connector) *DB {
	return &DB{conn: c}
}

// InsertDevice adds a `rr` registry record into the database in serialized
// bytes format.
func (d *DB) InsertDevice(ctx context.Context, rr *rpb.RegistryRecord) error {
	key := rr.DeviceId
	data, err := proto.Marshal(rr)
	if err != nil {
		return fmt.Errorf("failed to marshal registry record: %v", err)
	}
	return d.conn.Insert(ctx, key, rr.Sku, data)
}

// GetDevice returns a device record associated with a `di` device id. The
// result is returned in protobuf format.
func (d *DB) GetDevice(ctx context.Context, di string) (*rpb.RegistryRecord, error) {
	rr_bytes, err := d.conn.Get(ctx, di)
	if err != nil {
		return nil, err
	}
	record := &rpb.RegistryRecord{}
	if err := proto.Unmarshal(rr_bytes, record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registry record: %v", err)
	}
	return record, nil
}

func (d *DB) GetUnsyncedDevices(ctx context.Context, numDevices int) ([]*rpb.RegistryRecord, error) {
	raw_records, err := d.conn.GetUnsynced(ctx, numDevices)
	if err != nil {
		return nil, err
	}
	records := make([]*rpb.RegistryRecord, len(raw_records))
	for i, rr_bytes := range raw_records {
		record := &rpb.RegistryRecord{}
		if err := proto.Unmarshal(rr_bytes, record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal registry record: %v", err)
		}
		records[i] = record
	}
	return records, nil
}

func (d *DB) MarkDevicesAsSynced(ctx context.Context, dis []string) error {
	return d.conn.MarkAsSynced(ctx, dis)
}
