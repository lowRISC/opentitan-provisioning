// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package filedb implements a connector to a sqlite database.
package filedb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/connector"
)

const (
	UNSYNCED = iota
	SYNCED
)

type sqliteDB struct {
	db *gorm.DB
}

// deviceSchema represents the schema of the device table.
type deviceSchema struct {
	DeviceID  string `gorm:"primarykey"`
	SKU       string
	Device    []byte
	CreatedAt time.Time
	UpdatedAt time.Time
	SyncState int
}

var writeMutex sync.Mutex

// New creates a sqlite connector with an initialized gorm.DB instance.
func New(db_path string) (connector.Connector, error) {
	db, err := gorm.Open(sqlite.Open(db_path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA busy_timeout = 5000;")
	db.Exec("PRAGMA synchronous=NORMAL;")

	db.AutoMigrate(&deviceSchema{})
	return &sqliteDB{db: db}, nil
}

// Insert adds a `key` `value` pair to the database. Multiple calls with the
// same key will fail. Multiple calss with the same key will succeed.
func (s *sqliteDB) Insert(ctx context.Context, key, sku string, value []byte) error {
	writeMutex.Lock()
	defer writeMutex.Unlock()

	r := s.db.Create(&deviceSchema{DeviceID: key, SKU: sku, Device: value, SyncState: UNSYNCED})
	if r.Error != nil {
		return fmt.Errorf("failed to insert data with key: %q, error: %v", key, r.Error)
	}
	return nil
}

// Get gets the latest insterted value associated with a given `key`.
func (s *sqliteDB) Get(ctx context.Context, key string) ([]byte, error) {
	var device deviceSchema
	r := s.db.Last(&device, "device_id = ?", key)
	if r.Error != nil {
		return nil, fmt.Errorf("failed to get data associated with key: %q, error: %v", key, r.Error)
	}
	return device.Device, nil
}
