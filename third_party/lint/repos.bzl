# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def lint_repos(lowrisc_lint = None):
    http_archive(
        name = "bazelbuild_buildtools",
        sha256 = "05c3c3602d25aeda1e9dbc91d3b66e624c1f9fdadf273e5480b489e744ca7269",
        strip_prefix = "buildtools-6.4.0",
        url = "https://github.com/bazelbuild/buildtools/archive/refs/tags/v6.4.0.tar.gz",
    )
    http_archive(
        name = "protolint",
        sha256 = "f6073ee43c8f87d4a9a8479f5f806f3d3d06741534ae0facbe135a632c4e5988",
        build_file = Label("//third_party/lint:BUILD.protolint.bazel"),
        url = "https://github.com/yoheimuta/protolint/releases/download/v0.50.5/protolint_0.50.5_linux_amd64.tar.gz",
    )