# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@//rules:repo.bzl", "http_archive_or_local")

def crt_repos(local = None):
    maybe(
        http_archive_or_local,
        local = local,
        name = "crt",
        url = "https://github.com/lowRISC/crt/archive/refs/tags/v0.3.9.tar.gz",
        sha256 = "3f6e8e103595d2a6affbac5e2d9c14d1876f82fc6c8aca2a7528c97098a2f7ff",
        strip_prefix = "crt-0.3.9",
    )
