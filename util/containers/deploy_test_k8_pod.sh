#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

readonly REPO_TOP=$(git rev-parse --show-toplevel)

# Build release containers.
bazelisk build --stamp //release:provisioning_appliance_containers_tar
bazelisk build --stamp //release:softhsm_dev

# Deploy the provisioning appliance services.
export CONTAINERS_ONLY="yes"
. ${REPO_TOP}/config/dev/env/spm.env
${REPO_TOP}/config/dev/deploy.sh ${REPO_TOP}/bazel-bin/release

# Initialize and configure the HSM.
bazelisk run //src/spm:spmutil -- \
  --hsm_pw="${SPM_HSM_PIN_USER}" \
  --hsm_so="${OPENTITAN_VAR_DIR}/softhsm2/libsofthsm2.so" \
  --hsm_type=0 \
  --hsm_slot=0 \
  --force_keygen \
  --gen_kg \
  --gen_kca \
  --load_low_sec_ks \
  --low_sec_ks="0x23df79a8052010ef6e3d49255b606f871cff06170247c1145ebb71ad23834061" \
  --load_high_sec_ks \
  --high_sec_ks="0xaba9d5616e5a7c18b9a41d8a22f42d4dc3bafa9ca1fad01e404e708b1eab21fd" \
  --ca_outfile="${OPENTITAN_VAR_DIR}/spm/config/certs/NuvotonTPMRootCA0200.cer"

echo "Provisioning services launched."
echo "Run the following to teardown:"
echo "  podman pod stop provapp && podman pod rm provapp"
