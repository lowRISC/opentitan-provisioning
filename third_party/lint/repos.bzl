# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:util.bzl", "deb_package")
load("@//rules:repo.bzl", "http_archive_or_local")

def lint_repos(buildtools = None, protolint = None):
    http_archive_or_local(
        name = "bazelbuild_buildtools",
        local = buildtools,
        sha256 = "05c3c3602d25aeda1e9dbc91d3b66e624c1f9fdadf273e5480b489e744ca7269",
        strip_prefix = "buildtools-6.4.0",
        url = "https://github.com/bazelbuild/buildtools/archive/refs/tags/v6.4.0.tar.gz",
    )
    http_archive_or_local(
        name = "protolint",
        local = protolint,
        sha256 = "f6073ee43c8f87d4a9a8479f5f806f3d3d06741534ae0facbe135a632c4e5988",
        build_file = Label("//third_party/lint:BUILD.protolint.bazel"),
        url = "https://github.com/yoheimuta/protolint/releases/download/v0.50.5/protolint_0.50.5_linux_amd64.tar.gz",
    )
    deb_package(
        name = "clang-format",
        url = "http://ftp.us.debian.org/debian/pool/main/l/llvm-toolchain-14/clang-format-14_14.0.6-12_amd64.deb",
        sha256 = "3fbcadd614577667f6ff5958cc70b01fcf0b6a27f723a01516ced294b83d1002",
        build_file = Label("//third_party/lint:BUILD.clang-format.bazel"),
    )
