#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Explicitly enable job control so that we can run the SPM server
# in the background and still be able to run other commands in parallel.
set -m

# Build and deploy the provisioning infrastructure.
source util/integration_test_setup.sh

SKU_NAMES="sival,cr01,pi01,ti01"

# Run the PA loadtest.
echo "Running PA loadtest ..."
bazelisk run //src/pa:loadtest -- \
   --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
   --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
   --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
   --enable_tls=true \
   --hsm_so="${HSMTOOL_MODULE}" \
   --pa_address="${OTPROV_DNS_PA}:${OTPROV_PORT_PA}" \
   --parallel_clients=5 \
   --sku_auth="test_password" \
   --sku_names="${SKU_NAMES}" \
   --spm_config_dir="${DEPLOYMENT_DIR}/spm" \
   --total_duts=10
echo "Done."

# Run the CP and FT flows (default to hyper340 since that is installed in CI).
FPGA="${FPGA:-hyper340}"

if [[ "${FPGA}" == "skip" ]]; then
  echo "Skipping FPGA tests."
  exit 0
fi

if [[ "$FPGA" == "hyper340" ]]; then
  BIN_DEVICE="cw340"
else
  BIN_DEVICE="hyper310"
fi

FPGA_SKUS=(
  "sival"
)
# If OT_PROV_ORCHESTRATOR_PATH is set, then update the FPGA_SKUS to include the
# SKUs that are supported by the FPGA.
if [[ -n "${OT_PROV_ORCHESTRATOR_PATH}" ]]; then
  FPGA_SKUS+=("cr01" "pi01" "ti01")
fi

for OTSKU in "${FPGA_SKUS[@]}"; do
  # Workaround for the ti01 SKU, which is actually a ti00 SKU in the
  # orchestrator release.
  SKU_NAME="${OTSKU}"
  if [[ "${OTSKU}" == "ti01" ]]; then
    SKU_NAME="ti00"
  fi

  echo "Running CP FPGA test flow SKU: ${OTSKU} ..."
  bazelisk run //src/ate/test_programs:cp -- \
    --enable_mtls=true \
    --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
    --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
    --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
    --pa_target="ipv4:${OTPROV_IP_PA}:${OTPROV_PORT_PA}" \
    --sku="${OTSKU}" \
    --sku_auth_pw="test_password" \
    --fpga="${FPGA}" \
    --bitstream="$(pwd)/third_party/lowrisc/ot_bitstreams/cp_${FPGA}.bit" \
    --cp_sram_elf="${DEPLOYMENT_BIN_DIR}/sram_cp_provision_fpga_${BIN_DEVICE}_rom_with_fake_keys.elf" \
    --openocd="${DEPLOYMENT_BIN_DIR}/openocd"
  echo "Done."

  echo "Running FT FPGA test flow SKU: ${OTSKU} ..."
  bazelisk run //src/ate/test_programs:ft -- \
    --enable_mtls=true \
    --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
    --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
    --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
    --pa_target="ipv4:${OTPROV_IP_PA}:${OTPROV_PORT_PA_2}" \
    --sku="${OTSKU}" \
    --sku_auth_pw="test_password" \
    --fpga="${FPGA}" \
    --ft_individualization_elf="${DEPLOYMENT_BIN_DIR}/sram_ft_individualize_${SKU_NAME}_ate_fpga_${BIN_DEVICE}_rom_with_fake_keys.elf" \
    --ft_personalize_bin="${DEPLOYMENT_BIN_DIR}/ft_personalize_${SKU_NAME}_fpga_${BIN_DEVICE}_rom_with_fake_keys.signed.bin" \
    --ft_fw_bundle_bin="${DEPLOYMENT_BIN_DIR}/ft_fw_bundle_${SKU_NAME}_fpga_${BIN_DEVICE}_rom_with_fake_keys.img" \
    --openocd="${DEPLOYMENT_BIN_DIR}/openocd"
  echo "Done."
done
