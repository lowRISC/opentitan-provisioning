# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//third_party/crt/config:device.bzl", "device_config")

DEVICES = [
    device_config(
        name = "pc-win32",
        architecture = "x86_32",
        feature_set = "//third_party/crt/features/windows",
        constraints = [
            "@platforms//cpu:x86_32",
            "@platforms//os:windows",
        ],
        artifact_naming = [
            "//third_party/crt/features/windows:exe",
            "//third_party/crt/features/windows:dll",
        ],
    ),
]
