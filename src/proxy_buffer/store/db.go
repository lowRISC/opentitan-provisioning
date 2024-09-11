// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package db implements a database interface for the proxy buffer service.
package db

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/proto"

	dpb "github.com/lowRISC/opentitan-provisioning/src/proto/device_id_go_pb"
	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/connector"
)

const (
	// Database key template.
	// /pb/<record_type>/<device_type>/<device_identifier>
	recordKey = "/pb/dr/%08X/%016X"
)

// DB implements the Proxy Buffer database abstration layer.
type DB struct {
	// conn is the database connector interface.
	conn connector.Connector
}

// New creates a database `DB` instance with a given `c` databace connection.
func New(c connector.Connector) *DB {
	return &DB{conn: c}
}

// genKey generates a device key in string format from a `di` protobuf message.
func genKey(di *dpb.DeviceId) string {
	dt := uint32(dpb.SiliconCreatorId_value[di.HardwareOrigin.SiliconCreatorId.String()])
	dt = dt<<16 | uint32(di.HardwareOrigin.ProductId)
	return fmt.Sprintf(recordKey, dt, di.HardwareOrigin.DeviceIdentificationNumber)
}

// InsertDevice adds a `dr` device record into the database in serialized bytes
// format.
func (d *DB) InsertDevice(ctx context.Context, dr *dpb.DeviceRecord) error {
	key := genKey(dr.Id)
	data, err := proto.Marshal(dr)
	if err != nil {
		return fmt.Errorf("failed to marshal device record: %v", err)
	}
	return d.conn.Insert(ctx, key, data)
}

// GetDevice returns a device record associated with a `di` device id. The
// result is returned in protobuf format.
func (d *DB) GetDevice(ctx context.Context, di *dpb.DeviceId) (*dpb.DeviceRecord, error) {
	res, err := d.conn.Get(ctx, genKey(di))
	if err != nil {
		return nil, err
	}
	record := &dpb.DeviceRecord{}
	if err := proto.Unmarshal(res, record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device record: %v", err)
	}
	return record, nil
}
