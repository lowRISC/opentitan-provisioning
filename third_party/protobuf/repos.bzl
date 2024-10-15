# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")

_PROTOBUF_VERSION = "3.20.1"
_GRPC_VERSION = "1.52.0"

def protobuf_repos(protobuf = None, grpc = None):
    # Protobuf toolchain
    http_archive_or_local(
        name = "com_google_protobuf",
        local = protobuf,
        url = "https://github.com/protocolbuffers/protobuf/releases/download/v{}/protobuf-all-{}.tar.gz".format(_PROTOBUF_VERSION, _PROTOBUF_VERSION),
        sha256 = "3a400163728db996e8e8d21c7dfb3c239df54d0813270f086c4030addeae2fad",
        strip_prefix = "protobuf-{}".format(_PROTOBUF_VERSION),
    )

    #gRPC
    http_archive_or_local(
        name = "com_github_grpc_grpc",
        local = grpc,
        sha256 = "df9608a5bd4eb6d6b78df75908bb3390efdbbb9e07eddbee325e98cdfad6acd5",
        strip_prefix = "grpc-{}".format(_GRPC_VERSION),
        url = "https://github.com/grpc/grpc/archive/refs/tags/v{}.tar.gz".format(_GRPC_VERSION),
        patches = [
            Label("//third_party/protobuf:grpc-windows-constraints.patch"),
            Label("//third_party/protobuf:grpc-go-toolchain.patch"),
        ],
        patch_args = ["-p1"],
    )
