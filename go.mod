// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
module github.com/lowRISC/opentitan-provisioning

go 1.24.0

// This file is used to manage dependencies for the OpenTitan Provisioning
// project. It is used by the Go toolchain to fetch dependencies and their
// transitive dependencies.
//
// To update the dependencies, run `bazel run //:update-go-repos`.
//
// This project does not support the `go mod tidy` command.
require (
	// OpenTitan Provisioning core dependencies.
	github.com/golang/protobuf v1.5.3
	github.com/google/go-cmp v0.7.0
	github.com/google/tink/go v1.6.1
	github.com/jinzhu/inflection v1.0.0
	github.com/jinzhu/now v1.1.5

	// Required by gorm.
	github.com/mattn/go-sqlite3 v1.14.22
	github.com/miekg/pkcs11 v1.0.3
	golang.org/x/crypto v0.17.0
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.39.0
	// Required by Bazel golang infrastructure.
	golang.org/x/tools v0.17.0
	google.golang.org/api v0.62.0

	// Required by google.golang.org/grpc
	google.golang.org/genproto v0.0.0-20211208223120-3a66f561d7aa
	google.golang.org/grpc v1.43.0
	gorm.io/driver/sqlite v1.5.7

	// Proxy buffer backends.
	gorm.io/gorm v1.25.12
)

require (
	github.com/containerd/stargz-snapshotter/estargz v0.11.2 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v20.10.17+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker v28.5.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/glebarez/go-sqlite v1.21.2 // indirect
	github.com/glebarez/sqlite v1.11.0 // indirect
	github.com/google/go-containerregistry v0.8.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.15.0 // indirect
	github.com/magefile/mage v1.14.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/vbatts/tar-split v0.11.5 // indirect
	golang.org/x/exp v0.0.0-20200224162631-6cc2880d07d6 // indirect
	golang.org/x/text v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.43.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.7.2 // indirect
	modernc.org/sqlite v1.28.0 // indirect
)
