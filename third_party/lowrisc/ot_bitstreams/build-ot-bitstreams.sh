#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# This script makes it easy to build and check-in OT FPGA bitstreams for E2E
# testing.
#
# This script should be run from the root of this repo on a machine that also
# has the https://github.com/lowRISC/opentitan repo cloned and is configured to
# build bitstreams.

set -e

if [[ $# != 1 ]]; then
  echo "Usage: ./third_party/lowrisc/ot_bitstreams/build-ot-bitstreams.sh <OT repo top path>"
  exit 1
fi

OT_REPO_TOP=$1

_OT_REPO_BRANCH="Earlgrey-A2-Provisioning-RC8"
_PROVISIONING_REPO_TOP=$(pwd)
_FPGAS=("hyper310" "cw340")
_CP_SKUS=("emulation")
_BITSTREAM_PATH="bazel-bin/hw/bitstream/universal/splice.bit"

# Move to OT repo to build the bitstreams. This avoids polluting this project's
# bazel WORKSPACE just to build a couple of bitstream assets that are checked in
# to the repo.
cd "$OT_REPO_TOP"
git checkout $_OT_REPO_BRANCH
echo "Performing builds from: $(pwd)."

# Builds bitstreams for testing CP provisioning flows.
for fpga in "${_FPGAS[@]}"; do
  for sku in "${_CP_SKUS[@]}"; do
    echo "Building CP ${fpga} bitstream for ${sku} ..."
    bazelisk build \
      --//hw/bitstream/universal:otp=//hw/ip/otp_ctrl/data/earlgrey_skus/"$sku":otp_img_test_unlocked0_manuf_empty \
      --//hw/bitstream/universal:env=//hw/top_earlgrey:fpga_"$fpga"_rom_with_fake_keys \
      //hw/bitstream/universal:splice
    if [[ "$fpga" == "cw340" ]]; then
      cp -f "${_BITSTREAM_PATH}" "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_bitstreams/cp_hyper340.bit"
      chmod -x "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_bitstreams/cp_hyper340.bit"
    else
      cp -f "${_BITSTREAM_PATH}" "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_bitstreams/cp_${fpga}.bit"
      chmod -x "${_PROVISIONING_REPO_TOP}/third_party/lowrisc/ot_bitstreams/cp_${fpga}.bit"
    fi
  done
done

cd "$_PROVISIONING_REPO_TOP"
