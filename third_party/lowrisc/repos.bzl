# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@//rules:repo.bzl", "http_archive_or_local")

def lowrisc_repos(misc_linters = None, bazel_release = None):
    maybe(
        http_archive_or_local,
        name = "lowrisc_misc_linters",
        local = misc_linters,
        sha256 = "ff4e14b2a8ace83a7f6a1536c7489c29f8c2b97d345ae9bb8b2d0f68059ec265",
        strip_prefix = "misc-linters-20240423_01",
        url = "https://github.com/lowRISC/misc-linters/archive/refs/tags/20240423_01.tar.gz",
    )
    maybe(
        http_archive_or_local,
        local = bazel_release,
        name = "lowrisc_bazel_release",
        sha256 = "c7b0cbdec0a1081a0b0a52eb1ebd942e7eaa218408008661fdb6e8ec3b441a4a",
        strip_prefix = "bazel-release-0.0.3",
        url = "https://github.com/lowRISC/bazel-release/archive/refs/tags/v0.0.3.tar.gz",
    )
