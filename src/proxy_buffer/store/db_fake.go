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

// fakeDB is a fake database implementation. It implements the
// `connector.Connector` interface.
type fakeDB struct {
	// keyVersions is a map of plain keys to the lastest version number. The
	// number of records associated with a key is equivalent to the latest
	// version number.
	keyVersions map[string]uint32

	// db is a map of versioned keys to string values. This is the main
	// database storage container.
	db map[versionedKey][]byte
}

// New creates a database connector.
func New() connector.Connector {
	return &fakeDB{
		keyVersions: map[string]uint32{},
		db:          map[versionedKey][]byte{},
	}
}

// Insert adds a `key` `value` pair to the database. Multiple calls with the
// same key will succeed, emulating the behavior of an real database.
func (c *fakeDB) Insert(ctx context.Context, key string, value []byte) error {
	verK := versionedKey{key: key, version: 0}
	if ver, found := c.keyVersions[key]; found {
		verK.version = ver + 1
	}
	c.keyVersions[key] = verK.version
	c.db[verK] = value
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
	return c.db[verK], nil
}
