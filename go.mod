// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
module github.com/lowRISC/opentitan-provisioning

go 1.24.0

// This file is used to manage dependencies for the OpenTitan Provisioning
// project. It is used by the Go toolchain to fetch dependencies and their
// transitive dependencies.
//
// To update the dependencies, run `go get <package>` and then `bazel mod tidy`.
// To remove unused dependencies, run `go mod tidy` and then `bazel mod tidy`.
require (
	// OpenTitan Provisioning core dependencies.
	github.com/golang/protobuf v1.5.3
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.8.0
	github.com/google/tink/go v1.6.1
	github.com/jinzhu/inflection v1.0.0
	github.com/jinzhu/now v1.1.5
	github.com/miekg/pkcs11 v1.0.3
	github.com/pkg/errors v0.9.1
	golang.org/x/crypto v0.17.0
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.39.0

	// Required by Bazel golang infrastructure.
	golang.org/x/tools v0.17.0
	google.golang.org/api v0.62.0

	// Required by google.golang.org/grpc
	google.golang.org/genproto v0.0.0-20211208223120-3a66f561d7aa
	google.golang.org/grpc v1.43.0
	google.golang.org/protobuf v1.33.0

	// Required by gorm.
	gorm.io/gorm v1.25.12
	github.com/glebarez/go-sqlite v1.21.2
	github.com/glebarez/sqlite v1.11.0

	gopkg.in/yaml.v3 v3.0.1
)

// Indirect dependencies.
require (
	github.com/containerd/stargz-snapshotter/estargz v0.11.2
	github.com/distribution/reference v0.6.0
	github.com/docker/cli v20.10.17+incompatible
	github.com/docker/distribution v2.8.3+incompatible
	github.com/docker/docker v28.5.2+incompatible
	github.com/docker/docker-credential-helpers v0.8.2
	github.com/dustin/go-humanize v1.0.1
	github.com/fatih/color v1.15.0
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.15.0
	github.com/magefile/mage v1.14.0
	github.com/mattn/go-colorable v0.1.13
	github.com/mattn/go-isatty v0.0.20
	github.com/mitchellh/go-homedir v1.1.0
	github.com/ncruces/go-strftime v1.0.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec
	github.com/sirupsen/logrus v1.9.3
	github.com/vbatts/tar-split v0.11.5
	golang.org/x/exp v0.0.0-20200224162631-6cc2880d07d6
	golang.org/x/text v0.15.0
	modernc.org/libc v1.43.1
	modernc.org/mathutil v1.7.1
	modernc.org/memory v1.7.2
	modernc.org/sqlite v1.28.0
)
