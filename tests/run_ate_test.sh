#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Explicitly enable job control so that we can run the SPM server
# in the background and still be able to run other commands in parallel.
set -m

# Ensure we are running from the repository root
cd "$(dirname "$0")/.."

# Build and deploy the provisioning infrastructure.
source util/integration_test_setup.sh

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

# Populates the FPGA_SKUS array with the list of SKUs to test.
#
# Callers may override the default SKU list by passing FPGA_SKUS in the
# environment as a space-separated string (e.g., FPGA_SKUS="sival ti04").
# Because environment variables are imported by Bash as scalar strings,
# `read -r -a` is used to split the string into a Bash array so the test loop
# can iterate over each SKU individually.
if [[ -n "${FPGA_SKUS:-}" ]]; then
  read -r -a FPGA_SKUS <<< "${FPGA_SKUS}"
  return
else
  FPGA_SKUS=(
    "sival"
  )
  # If OT_PROV_ORCHESTRATOR_PATH is set, then update the FPGA_SKUS to include the
  # SKUs that are supported by the FPGA.
  if [[ -n "${OT_PROV_ORCHESTRATOR_PATH}" ]]; then
    FPGA_SKUS+=("cr01" "pi01" "ti01")
    if [[ -n "${OT_PROV_PQ_EN}" ]]; then
      FPGA_SKUS+=("ti04")
    fi
  fi
fi

for OTSKU in "${FPGA_SKUS[@]}"; do
  EXTRA_FT_FLAGS=()

  # Workaround for the ti01 and pi01 SKUs, which are actually the ti00 and pi02
  # SKUs in the orchestrator release.
  SKU_NAME="${OTSKU}"
  if [[ "${OTSKU}" == "ti01" ]]; then
    SKU_NAME="ti02"
  elif [[ "${OTSKU}" == "pi01" ]]; then
    SKU_NAME="pi02"
  fi

  if [[ -f "${DEPLOYMENT_BIN_DIR}/ft_flash_scramble_${SKU_NAME}_fpga_${BIN_DEVICE}_rom_with_fake_keys.signed.bin" ]]; then
    SCRAMBLE="ft_flash_scramble"
    EXTRA_FT_FLAGS+=("--use_flash_scramble=true")
  else
    SCRAMBLE="ft_personalize"
  fi

  if [[ "${OTSKU}" == "ti04" ]]; then
    EXTRA_FT_FLAGS+=("--enable_mldsa_dice=${ENABLE_MLDSA_DICE}")
  fi

  echo "Running CP FPGA test flow SKU: ${OTSKU} ..."
  bazelisk run //src/ate/test_programs:cp -- \
    --enable_mtls=true \
    --enable_mlkem_tls=${ENABLE_MLKEM_TLS} \
    --enable_mldsa_tls=${ENABLE_MLDSA_TLS} \
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
    --enable_mlkem_tls=${ENABLE_MLKEM_TLS} \
    --enable_mldsa_tls=${ENABLE_MLDSA_TLS} \
    --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
    --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
    --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
    --pa_target="ipv4:${OTPROV_IP_PA}:${OTPROV_PORT_PA_2}" \
    --sku="${OTSKU}" \
    --sku_auth_pw="test_password" \
    --fpga="${FPGA}" \
    --ft_individualization_elf="${DEPLOYMENT_BIN_DIR}/sram_ft_individualize_${SKU_NAME}_ate_fpga_${BIN_DEVICE}_rom_with_fake_keys.elf" \
    --ft_personalize_bin="${DEPLOYMENT_BIN_DIR}/${SCRAMBLE}_${SKU_NAME}_fpga_${BIN_DEVICE}_rom_with_fake_keys.signed.bin" \
    --ft_fw_bundle_bin="${DEPLOYMENT_BIN_DIR}/ft_fw_bundle_${SKU_NAME}_fpga_${BIN_DEVICE}_rom_with_fake_keys.img" \
    --openocd="${DEPLOYMENT_BIN_DIR}/openocd" \
    "${EXTRA_FT_FLAGS[@]}"
  echo "Done."
done
