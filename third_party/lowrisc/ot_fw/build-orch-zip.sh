#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# This script makes it easy to build and check-in OT provisioning firmware for
# E2E testing.
#
# This script should be run from the root of this repo on a machine that also
# has the https://github.com/lowRISC/opentitan repo cloned and is configured to
# build bitstreams.

set -e

if [[ $# != 1 ]]; then
  echo "Usage: ./third_party/lowrisc/ot_fw/build-orch-zip.sh <OT repo top path>"
  exit 1
fi

OT_REPO_TOP=$1

_OT_REPO_BRANCH="Earlgrey-A2-Orchestrator-RC3"
_PROVISIONING_REPO_TOP=$(pwd)
_ORCHESTRATOR_ZIP_PATH="bazel-bin/sw/host/provisioning/orchestrator/src/orchestrator.zip"

# Move to OT repo to build the firmware ZIP package. This avoids polluting this
# project's bazel WORKSPACE just to build a ZIP release package.
cd "$OT_REPO_TOP"
# Ensure we only build upstream firmware.
unset PROV_EXTS_DIR
git checkout $_OT_REPO_BRANCH
echo "Performing builds from: $(pwd)."

# Builds firmware for testing CP & FT provisioning flows.
# Note: the FPGA/OTP images set via cmd line switches are just placeholders. The
# FPGA bitstreams used to run test flows are also checked into this repo; the
# one included in the ZIP package is unused.
echo "Building orchestrator.zip provisioning firmware release ..." 
bazelisk build \
  --//hw/bitstream/universal:otp=//hw/ip/otp_ctrl/data/earlgrey_skus/emulation:otp_img_test_unlocked0_manuf_empty \
  --//hw/bitstream/universal:env=//hw/top_earlgrey:fpga_cw340_rom_with_fake_keys \
  //sw/host/provisioning/orchestrator/src:orchestrator.zip
cp -f "${_ORCHESTRATOR_ZIP_PATH}" "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_fw/orchestrator.zip"
chmod -x "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_fw/orchestrator.zip"

cd "$_PROVISIONING_REPO_TOP"
