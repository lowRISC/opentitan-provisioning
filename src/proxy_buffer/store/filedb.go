// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package filedb implements a connector to a sqlite database.
package filedb

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// Close closes a sqlite connector.
func Close(c connector.Connector) error {
	sDB, ok := c.(*sqliteDB)
	if !ok {
		return errors.New("connector type is not a SQLite object")
	}
	dbObject, err := sDB.db.DB()
	if err != nil {
		return fmt.Errorf("failed to access DB object: %v", err)
	}
	if err := dbObject.Close(); err != nil {
		return fmt.Errorf("failed to close DB: %v", err)
	}
	return nil
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

func (s *sqliteDB) GetUnsynced(ctx context.Context, numRecords int) ([][]byte, error) {
	devices := make([]*deviceSchema, 0)
	r := s.db.Limit(numRecords).Where("sync_state = ?", UNSYNCED).Find(&devices)
	if r.Error != nil {
		return nil, fmt.Errorf("failed to get all unsynced devices: %v", r.Error)
	}
	results := make([][]byte, len(devices))
	for i, device := range devices {
		results[i] = device.Device
	}
	return results, nil
}

func (s *sqliteDB) MarkAsSynced(ctx context.Context, keys []string) error {
	writeMutex.Lock()
	defer writeMutex.Unlock()

	return s.db.Transaction(func(tx *gorm.DB) error {
		failed := make([]string, 0)
		for _, key := range keys {
			var device deviceSchema
			if err := tx.Model(&device).Where("device_id = ?", key).Update("sync_state", SYNCED).Error; err != nil {
				failed = append(failed, key)
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("failed to mark devices as synced: %s", strings.Join(failed, ", "))
		}
		return nil
	})
}
