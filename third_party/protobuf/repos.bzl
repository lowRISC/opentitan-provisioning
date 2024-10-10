# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

_PROTOBUF_VERSION = "3.17.3"
_GRPC_VERSION = "1.45.0"

def protobuf_repos():
    # Protobuf toolchain
    http_archive(
        name = "com_google_protobuf",
        url = "https://github.com/protocolbuffers/protobuf/releases/download/v{}/protobuf-all-{}.tar.gz".format(_PROTOBUF_VERSION, _PROTOBUF_VERSION),
        sha256 = "77ad26d3f65222fd96ccc18b055632b0bfedf295cb748b712a98ba1ac0b704b2",
        strip_prefix = "protobuf-{}".format(_PROTOBUF_VERSION),
    )

    #gRPC
    http_archive(
        name = "com_github_grpc_grpc",
        sha256 = "ec19657a677d49af59aa806ec299c070c882986c9fcc022b1c22c2a3caf01bcd",
        strip_prefix = "grpc-{}".format(_GRPC_VERSION),
        url = "https://github.com/grpc/grpc/archive/refs/tags/v{}.tar.gz".format(_GRPC_VERSION),
        patches = [Label("//third_party/google:grpc-windows-constraints.patch")],
        patch_args = ["-p1"],
    )
