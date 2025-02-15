# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")

_RULES_GO_VERSION = "0.41.0"
_GAZELLE_VERSION = "0.35.0"

def go_repos(rules_go = None, gazelle = None):
    # Go toolchain
    http_archive_or_local(
        name = "io_bazel_rules_go",
        local = rules_go,
        sha256 = "278b7ff5a826f3dc10f04feaf0b70d48b68748ccd512d7f98bf442077f043fe3",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v{}/rules_go-v{}.zip".format(_RULES_GO_VERSION, _RULES_GO_VERSION),
            "https://github.com/bazelbuild/rules_go/releases/download/v{}/rules_go-v{}.zip".format(_RULES_GO_VERSION, _RULES_GO_VERSION),
        ],
    )

    # Gazelle go version management
    http_archive_or_local(
        name = "bazel_gazelle",
        local = gazelle,
        sha256 = "32938bda16e6700063035479063d9d24c60eda8d79fd4739563f50d331cb3209",
        url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/v{}/bazel-gazelle-v{}.tar.gz".format(_GAZELLE_VERSION, _GAZELLE_VERSION),
    )
