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
    # BoringSSL.
    http_archive_or_local(
        name = "boringssl",
        local = boringssl,
        # Use github mirror instead of https://boringssl.googlesource.com/boringssl
        # to obtain a boringssl archive with consistent sha256
        sha256 = "534fa658bd845fd974b50b10f444d392dfd0d93768c4a51b61263fd37d851c40",
        strip_prefix = "boringssl-b9232f9e27e5668bc0414879dcdedb2a59ea75f2",
        urls = [
            "https://storage.googleapis.com/grpc-bazel-mirror/github.com/google/boringssl/archive/b9232f9e27e5668bc0414879dcdedb2a59ea75f2.tar.gz",
            "https://github.com/google/boringssl/archive/b9232f9e27e5668bc0414879dcdedb2a59ea75f2.tar.gz",
        ],
        patches = [Label("//third_party/google:boringssl-windows-constraints.patch")],
        patch_args = ["-p1"],
    )

    # Regular Expression Library.
    http_archive_or_local(
        name = "com_googlesource_code_re2",
        local = re2,
        url = "https://github.com/google/re2/archive/refs/tags/{}.tar.gz".format(_RE2_VERSION),
        strip_prefix = "re2-{}".format(_RE2_VERSION),
        sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
    )

    # Googletest https://google.github.io/googletest/
    http_archive_or_local(
        name = "googletest",
        local = googletest,
        url = "https://github.com/google/googletest/archive/refs/tags/v{}.tar.gz".format(_GOOGLETEST_VERSION),
        strip_prefix = "googletest-{}".format(_GOOGLETEST_VERSION),
        sha256 = "8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
    )

    # Protobuf matchers for googletest.
    http_archive_or_local(
        name = "com_github_protobuf_matchers",
        local = pbuf_matchers,
        urls = ["https://github.com/inazarenko/protobuf-matchers/archive/7c8e15741bcea83db7819cc472c3e96301a95158.zip"],
        strip_prefix = "protobuf-matchers-7c8e15741bcea83db7819cc472c3e96301a95158",
        build_file_content = "package(default_visibility = [\"//visibility:public\"])",
        sha256 = "8314521014fb7b5e33f061d0f53a3c7222dbee1871df2f66198522a5687a71c1",
    )

    # Abseil https://abseil.io/
    http_archive_or_local(
        name = "com_google_absl",
        local = absl,
        url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/{}.tar.gz".format(_ABSL_VERSION),
        strip_prefix = "abseil-cpp-{}".format(_ABSL_VERSION),
        sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
    )
