# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_MISC_LINTERS_VERSION = "20240820_01"
_BAZEL_RELEASE_VERSION = "0.0.3"
_BAZEL_SKYLIB_VERSION = "1.7.1"

# When updating the lowrisc_opentitan repo, be sure to rebuild the builtstream
# files too by following the instructions in
# `third_party/lowrisc/README.md`.
_OPENTITAN_VERSION = "Earlgrey-A2-Orchestrator-RC2"

def lowrisc_repos(misc_linters = None, bazel_release = None, bazel_skylib = None, opentitan = None):
    maybe(
        http_archive_or_local,
        local = bazel_release,
        name = "lowrisc_bazel_release",
        sha256 = "c7b0cbdec0a1081a0b0a52eb1ebd942e7eaa218408008661fdb6e8ec3b441a4a",
        strip_prefix = "bazel-release-{}".format(_BAZEL_RELEASE_VERSION),
        url = "https://github.com/lowRISC/bazel-release/archive/refs/tags/v{}.tar.gz".format(_BAZEL_RELEASE_VERSION),
    )
