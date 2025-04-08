// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package db_fake implements a fake database backend which can be used for
// testing purposes.
package db_fake

import (
	"context"
	"fmt"

	"github.com/lowRISC/opentitan-provisioning/src/proxy_buffer/store/connector"
)

// versionedKey implements a versioned key which can be used as a key in a map.
type versionedKey struct {
	key     string
	version uint32
}

const (
	recordStatusUnsynced = iota
	recordStatusSynced
)

// record contains data about a record and its sync state
type record struct {
	// value is the raw data of a record
	value []byte
	// status indicates the record's sync status
	status int
}

// fakeDB is a fake database implementation. It implements the
// `connector.Connector` interface.
type fakeDB struct {
	// keyVersions is a map of plain keys to the lastest version number. The
	// number of records associated with a key is equivalent to the latest
	// version number.
	keyVersions map[string]uint32

	// db is a map of versioned keys to record values. This is the main
	// database storage container.
	db map[versionedKey]record
}

// New creates a database connector.
func New() connector.Connector {
	return &fakeDB{
		keyVersions: map[string]uint32{},
		db:          map[versionedKey]record{},
	}
}

// Insert adds a `key` `value` pair to the database. Multiple calls with the
// same key will succeed, emulating the behavior of an real database.
func (c *fakeDB) Insert(ctx context.Context, key, sku string, value []byte) error {
	verK := versionedKey{key: key, version: 0}
	if ver, found := c.keyVersions[key]; found {
		verK.version = ver + 1
	}
	c.keyVersions[key] = verK.version
	c.db[verK] = record{
		value:  value,
		status: recordStatusUnsynced,
	}
	return nil
}

// Get gets the latest insterted value associated with a given `key`.
func (c *fakeDB) Get(ctx context.Context, key string) ([]byte, error) {
	verK := versionedKey{key: key}
	ver, found := c.keyVersions[key]
	if !found {
		return nil, fmt.Errorf("record not found key: %q", key)
	}
	verK.version = ver
	return c.db[verK].value, nil
}

// GetUnsynced returns up to `numRecords` UNSYNCED records.
func (c *fakeDB) GetUnsynced(ctx context.Context, numRecords int) ([][]byte, error) {
	records := make([][]byte, 0)
	processedUnsyncedCount := 0
	for _, record := range c.db {
		if processedUnsyncedCount == numRecords {
			break
		}
		if record.status == recordStatusUnsynced {
			records = append(records, record.value)
			processedUnsyncedCount += 1
		}
	}
	return records, nil
}

// MarkAsSynced marks all records in `keys` as SYNCED.
func (c *fakeDB) MarkAsSynced(ctx context.Context, keys []string) error {
	for _, key := range keys {
		verK := versionedKey{key: key}
		ver, found := c.keyVersions[key]
		if !found {
			return fmt.Errorf("record not found key: %q", key)
		}
		verK.version = ver
		record := c.db[verK]
		record.status = recordStatusSynced
		c.db[verK] = record
	}
	return nil
}
