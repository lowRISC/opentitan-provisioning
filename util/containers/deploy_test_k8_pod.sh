#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

readonly REPO_TOP=$(git rev-parse --show-toplevel)

# Build release containers.
bazelisk build --stamp //release:provisioning_appliance_containers_tar
bazelisk build --stamp //release:proxybuffer_containers_tar
bazelisk build --stamp //release:softhsm_dev
bazelisk build --stamp //release:hsmtool

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
  --ca_outfile="${OPENTITAN_VAR_DIR}/spm/config/certs/NuvotonTPMRootCA0200.cer"

# Import keys for SiVal SKU.
echo "hsmtool: importing keys for SiVal SKU..."
${OPENTITAN_VAR_DIR}/bin/hsmtool \
  --pin="${SPM_HSM_PIN_USER}" \
  --module="${OPENTITAN_VAR_DIR}/softhsm2/libsofthsm2.so" \
  --token="${SPM_HSM_TOKEN_LABEL}" \
  --user=user exec ${OPENTITAN_VAR_DIR}/spm/config/sku/sival/import.hjson
echo "Done."

echo "Provisioning services launched."
echo "Run the following to teardown:"
echo "  podman pod stop provapp && podman pod rm provapp"
