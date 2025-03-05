// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
module github.com/lowRISC/opentitan-provisioning

go 1.19

replace github.com/lowRISC/opentitan-provisioning => ./

// This file is used to manage dependencies for the OpenTitan Provisioning
// project. It is used by the Go toolchain to fetch dependencies and their
// transitive dependencies.
//
// To update the dependencies, run `bazel run //:update-go-repos`.
//
// This project does not support the `go mod tidy` command.
require (
	// OpenTitan Provisioning core dependencies.
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.6.0
	github.com/google/tink/go v1.6.1
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect

	// Required by gorm.
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/miekg/pkcs11 v1.0.3
	golang.org/x/crypto v0.31.0
	golang.org/x/sync v0.10.0
	golang.org/x/sys v0.28.0 // indirect
	google.golang.org/grpc v1.67.3
	gorm.io/driver/sqlite v1.5.7

	// Proxy buffer backends.
	gorm.io/gorm v1.25.12
)

require (
	github.com/bazelbuild/rules_go v0.53.0
	google.golang.org/protobuf v1.36.3
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)

require (
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)
