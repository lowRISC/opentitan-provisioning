# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(default_visibility = ["//visibility:public"])

go_library(
    name = "dututils",
    testonly = True,
    srcs = ["dututils.go"],
    importpath = "github.com/lowRISC/opentitan-provisioning/src/ate/dututils",
    visibility = ["//visibility:public"],
    deps = [
        "//src/ate:ate_go_lib",
        "//src/ate/proto:dut_commands_go_proto",
        "//src/proto:device_id_go_pb",
        "//src/proto:device_testdata",
        "//src/spm/services/skumgr",
        "//src/spm/services/testutils:tbsgen",
        "//src/utils:devid",
    ],
)
