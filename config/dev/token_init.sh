#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

CONFIG_DIR="$(realpath "$(dirname "$0")")"

source "${CONFIG_DIR}/env/spm.env"

SKU_CONFIG_FILES=(
  "${CONFIG_DIR}/spm/sku/hsm_spm_init.sh"
  "${CONFIG_DIR}/spm/sku/sival/hsm_sku_init.sh"
  "${CONFIG_DIR}/spm/sku/tpm_1/hsm_sku_init.sh"
)

# Check token initialization dependencies.
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

if [ ! -x "${OPENTITAN_VAR_DIR}/bin/certgen" ]; then
  echo "Error: '${OPENTITAN_VAR_DIR}/bin/certgen' is not executable or does not exist."
  return 1
fi

function run_hsm_init() {
  local init_script="$1"
  local original_dir="$(pwd)"

   trap 'cd "$original_dir" || { echo "Error: Could not change back to original directory '${init_script}'."; return 1; }' EXIT

  if [ ! -f "${init_script}" ]; then
    echo "Error: File '${init_script}' does not exist."
    return 1
  fi

  local file_dir="$(dirname "${init_script}")"

  cd "${file_dir}" || {
    echo "Error: Could not change directory to '${init_script}'."
    return 1
  }

  echo "Running HSM initialization script: ${init_script}"
  "${init_script}"
}

for filename in "${SKU_CONFIG_FILES[@]}"; do
  echo "Processing file: ${filename}"
  run_hsm_init "${filename}"
  if [ "$?" -ne 0 ]; then
    echo "Error processing file: ${filename}."
    exit 1
  fi
  echo "-------------------------"
done

echo "HSM initialization complete."

