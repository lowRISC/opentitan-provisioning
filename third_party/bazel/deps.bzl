# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

def bazel_deps():
    rules_foreign_cc_dependencies()
    rules_pkg_dependencies()
    bazel_skylib_workspace()
