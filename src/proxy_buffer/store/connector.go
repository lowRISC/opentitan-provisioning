// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Package connector implements a database connector interface.
package connector

import (
	"context"
)

// Connector implements a connection to the database.
type Connector interface {
	// Insert a `key` `value` pair to the database.
	// It should respect context cancellation and timeout.
	Insert(ctx context.Context, key, sku string, value []byte) error

	// Get returns a value associated with a given `key`.
	// It should respect context cancellation and timeout.
	Get(ctx context.Context, key string) ([]byte, error)
}
