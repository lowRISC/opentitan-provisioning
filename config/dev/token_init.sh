#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

CONFIG_DIR="$(realpath "$(dirname "$0")")"

source "${CONFIG_DIR}/env/spm.env"

export HSMTOOL_BIN="${OPENTITAN_VAR_DIR}/bin/hsmtool"

# Check token initialization dependencies.
if [ -z "${OPENTITAN_VAR_DIR}" ]; then
  echo "Error: OPENTITAN_VAR_DIR environment variable is not set."
  return 1
fi

if [ ! -d "${OPENTITAN_VAR_DIR}" ]; then
  echo "Error: OPENTITAN_VAR_DIR directory '${OPENTITAN_VAR_DIR}' does not exist."
  return 1
fi

if [ ! -x "${HSMTOOL_BIN}" ]; then
  echo "Error: '${HSMTOOL_BIN}' is not executable or does not exist."
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

  shift

  echo "Running HSM initialization script: ${init_script}"
  "${init_script}" "$@"
}

# Run the HSM initialization script for SPM.
run_hsm_init "${CONFIG_DIR}/spm/sku/hsm_spm_init.sh" \
  -o "${CONFIG_DIR}/spm/sku/spm_hsm_init.tar.gz"

# Run the SKU initilization script in the offline HSM partition.
run_hsm_init "${CONFIG_DIR}/spm/sku/sival/hsm_offline_init.sh" \
  -i "${CONFIG_DIR}/spm/sku/spm_hsm_init.tar.gz" \
  -o "${CONFIG_DIR}/spm/sku/sival/hsm_offline_init.tar.gz"

# Run the SKU initialization script in the SPM partition.
run_hsm_init "${CONFIG_DIR}/spm/sku/sival/hsm_spm_init.sh" \
  -i "${CONFIG_DIR}/spm/sku/sival/hsm_offline_init.tar.gz" \
  -o "${CONFIG_DIR}/spm/sku/sival/hsm_sival_sku.tar.gz"

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
