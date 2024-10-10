# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def google_repos():
    http_archive(
        name = "boringssl",
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
    http_archive(
        name = "com_googlesource_code_re2",
        urls = ["https://github.com/google/re2/archive/refs/tags/2022-12-01.tar.gz"],
        strip_prefix = "re2-2022-12-01",
        sha256 = "665b65b6668156db2b46dddd33405cd422bd611352c5052ab3dae6a5fbac5506",
    )

    # Googletest https://google.github.io/googletest/
    http_archive(
        name = "com_google_googletest",
        urls = ["https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz"],
        strip_prefix = "googletest-1.13.0",
        sha256 = "ad7fdba11ea011c1d925b3289cf4af2c66a352e18d4c7264392fead75e919363",
    )

    # Protobuf matchers for googletest.
    http_archive(
        name = "com_github_protobuf_matchers",
        urls = ["https://github.com/inazarenko/protobuf-matchers/archive/7c8e15741bcea83db7819cc472c3e96301a95158.zip"],
        strip_prefix = "protobuf-matchers-7c8e15741bcea83db7819cc472c3e96301a95158",
        build_file_content = "package(default_visibility = [\"//visibility:public\"])",
        sha256 = "8314521014fb7b5e33f061d0f53a3c7222dbee1871df2f66198522a5687a71c1",
    )

    # Abseil https://abseil.io/
    http_archive(
        name = "com_google_absl",
        urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz"],
        strip_prefix = "abseil-cpp-20230125.0",
        sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
    )
