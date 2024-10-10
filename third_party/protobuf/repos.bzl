# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

_PROTOBUF_VERSION = "3.20.1"
_GRPC_VERSION = "1.52.0"

def protobuf_repos():
    # Protobuf toolchain
    http_archive(
        name = "com_google_protobuf",
        url = "https://github.com/protocolbuffers/protobuf/releases/download/v{}/protobuf-all-{}.tar.gz".format(_PROTOBUF_VERSION, _PROTOBUF_VERSION),
        sha256 = "3a400163728db996e8e8d21c7dfb3c239df54d0813270f086c4030addeae2fad",
        strip_prefix = "protobuf-{}".format(_PROTOBUF_VERSION),
    )

    #gRPC
    http_archive(
        name = "com_github_grpc_grpc",
        sha256 = "df9608a5bd4eb6d6b78df75908bb3390efdbbb9e07eddbee325e98cdfad6acd5",
        strip_prefix = "grpc-{}".format(_GRPC_VERSION),
        url = "https://github.com/grpc/grpc/archive/refs/tags/v{}.tar.gz".format(_GRPC_VERSION),
        patches = [
            Label("//third_party/protobuf:grpc-windows-constraints.patch"),
            Label("//third_party/protobuf:grpc-go-toolchain.patch"),
        ],
        patch_args = ["-p1"],
    )
