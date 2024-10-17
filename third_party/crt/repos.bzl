# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("@//rules:repo.bzl", "http_archive_or_local")

_CRT_VERSION = "0.4.14"

def crt_repos(local = None):
    maybe(
        http_archive_or_local,
        local = local,
        name = "crt",
        url = "https://github.com/lowRISC/crt/archive/refs/tags/v{}.tar.gz".format(_CRT_VERSION),
        sha256 = "aad71e39d0361d3eede8cb889d5ffb3a560108671598b01a4b6deadcfe75d6a6",
        strip_prefix = "crt-{}".format(_CRT_VERSION),
    )
