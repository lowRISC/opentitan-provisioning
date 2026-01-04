# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//config:device.bzl", "device_config")

DEVICES = [
    device_config(
        name = "pc-win32",
        architecture = "x86_32",
        feature_set = "//features/windows",
        constraints = [
            "@platforms//cpu:x86_32",
            "@platforms//os:windows",
        ],
        artifact_naming = [
            "//features/windows:exe",
            "//features/windows:dll",
        ],
    ),
]
