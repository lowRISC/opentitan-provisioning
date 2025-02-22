#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

CONFIG_DIR="$(realpath "$(dirname "$0")")"

source "${CONFIG_DIR}/env/spm.env"

SKU_CONFIG_FILES=(
  "${CONFIG_DIR}/spm/sku/tpm_1/init.hjson"
  "${CONFIG_DIR}/spm/sku/sival/init.hjson"
)

function run_hsmtool() {
  local filename="$1"
  local original_dir="$(pwd)"

   trap 'cd "$original_dir" || { echo "Error: Could not change back to original directory '${original_dir}'."; return 1; }' EXIT

  if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' does not exist."
    return 1
  fi

  local file_dir="$(dirname "$filename")"

  cd "$file_dir" || {
    echo "Error: Could not change directory to '$file_dir'."
    return 1
  }

  if [ -z "${OPENTITAN_VAR_DIR}" ]; then
    echo "Error: OPENTITAN_VAR_DIR environment variable is not set."
    return 1
  fi

  if [ ! -d "${OPENTITAN_VAR_DIR}" ]; then
    echo "Error: OPENTITAN_VAR_DIR directory '${OPENTITAN_VAR_DIR}' does not exist."
    return 1
  fi

  if [ ! -x "${OPENTITAN_VAR_DIR}/bin/hsmtool" ]; then
    echo "Error: '${OPENTITAN_VAR_DIR}/bin/hsmtool' is not executable or does not exist."
    return 1
  fi

  "${OPENTITAN_VAR_DIR}/bin/hsmtool" --logging=info exec "${filename}"
}

for filename in "${SKU_CONFIG_FILES[@]}"; do
  echo "Processing file: ${filename}"
  run_hsmtool "${filename}"
  if [ "$?" -ne 0 ]; then
    echo "Error processing file: ${filename}."
    exit 1
  fi
  echo "-------------------------"
done

echo "Creating test root CA certificats"
"${OPENTITAN_VAR_DIR}/bin/certgen" \
  --hsm_pw="${HSMTOOL_PIN}"        \
  --hsm_so="${HSMTOOL_MODULE}"     \
  --hsm_slot=0                     \
  --ca_key_label="KCAPriv"         \
  --ca_outfile="${OPENTITAN_VAR_DIR}/spm/certs/NuvotonTPMRootCA0200.cer"

echo "HSM initialization complete."

