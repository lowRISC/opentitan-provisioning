# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "dut_commands_proto",
    srcs = ["dut_commands.proto"],
)

cc_proto_library(
    name = "dut_commands_cc_proto",
    deps = [":dut_commands_proto"],
)

go_proto_library(
    name = "dut_commands_go_proto",
    importpath = "github.com/lowRISC/opentitan-provisioning/src/ate/proto/dut_commands_go_pb",
    proto = ":dut_commands_proto",
)
