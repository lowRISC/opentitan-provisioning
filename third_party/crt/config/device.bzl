# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def device_config(
        name,
        architecture,
        constraints,
        feature_set = "//third_party/crt/features/common",
        artifact_naming = [],
        substitutions = {}):
    """Creates a device_config struct.

    The device_config struct is an instantiation of a given platform.  The
    device config structs are used to configure toolchains.  As such, there
    should be a one-to-one correspondence between named platforms and
    device configs.

    Args:
      name: str; the name of the device configuration.
      architecture: str; the name of the device architecture (e.g. x86_64).
      constraints: list[label]; the platform constraints for this device.
      artifact_naming: list[label]; a list of artifact naming conventions for
                       this device (e.g. ".exe" for windows platforms).
      substitutions: dict[str, str]; a set of substitutions to apply to the
                     feature_set when bulding the toolchain configuration.
    """
    return struct(
        name = name,
        architecture = architecture,
        constraints = constraints,
        feature_set = feature_set,
        artifact_naming = artifact_naming,
        substitutions = substitutions,
    )
