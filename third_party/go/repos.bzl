# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

_RULES_GO_VERSION = "0.34.0"
_GAZELLE_VERSION = "0.24.0"

def go_repos():
    # Go toolchain
    http_archive(
        name = "io_bazel_rules_go",
        sha256 = "16e9fca53ed6bd4ff4ad76facc9b7b651a89db1689a2877d6fd7b82aa824e366",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v{}/rules_go-v{}.zip".format(_RULES_GO_VERSION, _RULES_GO_VERSION),
            "https://github.com/bazelbuild/rules_go/releases/download/v{}/rules_go-v{}.zip".format(_RULES_GO_VERSION, _RULES_GO_VERSION),
        ],
    )

    # Gazelle go version management
    http_archive(
        name = "bazel_gazelle",
        sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
        url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/v{}/bazel-gazelle-v{}.tar.gz".format(_GAZELLE_VERSION, _GAZELLE_VERSION),
    )
