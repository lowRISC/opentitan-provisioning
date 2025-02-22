# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

_MISC_LINTERS_VERSION = "20240820_01"
_BAZEL_RELEASE_VERSION = "0.0.3"
_BAZEL_SKYLIB_VERSION = "1.5.0"
_OPENTITAN_VERSION = "Earlgrey-A2-Provisioning-RC2"

def lowrisc_repos(misc_linters = None, bazel_release = None, bazel_skylib = None, opentitan = None):
    maybe(
        http_archive_or_local,
        name = "lowrisc_misc_linters",
        local = misc_linters,
        sha256 = "1303d2790b7d1a0a216558c01f8bc6255dfb840e9e60b523d988b3655a0ddab3",
        strip_prefix = "misc-linters-{}".format(_MISC_LINTERS_VERSION),
        url = "https://github.com/lowRISC/misc-linters/archive/refs/tags/{}.tar.gz".format(_MISC_LINTERS_VERSION),
    )
    maybe(
        http_archive_or_local,
        local = bazel_release,
        name = "lowrisc_bazel_release",
        sha256 = "c7b0cbdec0a1081a0b0a52eb1ebd942e7eaa218408008661fdb6e8ec3b441a4a",
        strip_prefix = "bazel-release-{}".format(_BAZEL_RELEASE_VERSION),
        url = "https://github.com/lowRISC/bazel-release/archive/refs/tags/v{}.tar.gz".format(_BAZEL_RELEASE_VERSION),
    )
    maybe(
        http_archive_or_local,
        name = "bazel_skylib",
        lcoal = bazel_skylib,
        sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
        url = "https://github.com/bazelbuild/bazel-skylib/releases/download/{}/bazel-skylib-{}.tar.gz".format(
            _BAZEL_SKYLIB_VERSION,
            _BAZEL_SKYLIB_VERSION,
        ),
    )
    maybe(
        http_archive_or_local,
        local = opentitan,
        name = "lowrisc_opentitan",
        sha256 = "640d2f080a8677fa396028371b8224fabdd197689b32a44952cae49b93c75146",
        strip_prefix = "opentitan-{}".format(_OPENTITAN_VERSION),
        url = "https://github.com/lowRISC/opentitan/archive/refs/tags/{}.tar.gz".format(_OPENTITAN_VERSION),
    )
