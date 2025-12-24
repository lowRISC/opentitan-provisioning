# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")

_RE2_VERSION = "2024-02-01"
_GOOGLETEST_VERSION = "1.14.0"
_ABSL_VERSION = "20230125.0"

def google_repos(
        boringssl = None,
        re2 = None,
        googletest = None,
        pbuf_matchers = None,
        absl = None):
    # Regular Expression Library.
    http_archive_or_local(
        name = "com_googlesource_code_re2",
        local = re2,
        url = "https://github.com/google/re2/archive/refs/tags/{}.tar.gz".format(_RE2_VERSION),
        strip_prefix = "re2-{}".format(_RE2_VERSION),
        sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
    )

    # Protobuf matchers for googletest.
    http_archive_or_local(
        name = "com_github_protobuf_matchers",
        local = pbuf_matchers,
        urls = ["https://github.com/inazarenko/protobuf-matchers/archive/7c8e15741bcea83db7819cc472c3e96301a95158.zip"],
        strip_prefix = "protobuf-matchers-7c8e15741bcea83db7819cc472c3e96301a95158",
        build_file_content = "package(default_visibility = [\"//visibility:public\"])",
        sha256 = "8314521014fb7b5e33f061d0f53a3c7222dbee1871df2f66198522a5687a71c1",
        patches = [Label("//third_party/google:protobuf_matchers_fix.patch")],
        patch_args = ["-p1"],
    )
