#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

if [[ -z "${DEPLOY_ENV}" ]]; then
  echo "Error: DEPLOY_ENV environment variable is not set."
  exit 1
fi

CONFIG_DIR="${OPENTITAN_VAR_DIR}/config"
SPM_SKU_DIR="${CONFIG_DIR}/spm/sku"
SPM_SKU_EG_DIR="${SPM_SKU_DIR}/eg"

# Supported SKU directories.
SIVAL_DIR="${SPM_SKU_DIR}/sival"
EG_COMMON_DIR="${SPM_SKU_EG_DIR}/common"
EG_CR_DIR="${SPM_SKU_EG_DIR}/cr"
EG_PI_DIR="${SPM_SKU_EG_DIR}/pi"
EG_TI_DIR="${SPM_SKU_EG_DIR}/ti"

SKU_DIRS=("${SIVAL_DIR}" "${EG_CR_DIR}" "${EG_PI_DIR}" "${EG_TI_DIR}")

# Common HSM archive filenames
HSM_CA_INTERMEDIATE_CSR_TAR_GZ="hsm_ca_intermediate_csr.tar.gz"
HSM_CA_INTERMEDIATE_CERTS_TAR_GZ="hsm_ca_intermediate_certs.tar.gz"
HSM_CA_ROOT_CERTS_TAR_GZ="hsm_ca_root_certs.tar.gz"

# Source environment variables or exit with error
source "${CONFIG_DIR}/env/${DEPLOY_ENV}/spm.env" || {
  echo "Error: Failed to source ${CONFIG_DIR}/env/${DEPLOY_ENV}/spm.env"
  exit 1
}

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

  trap 'cd "${original_dir}" || { echo "Error: Could not change back to original directory '${original_dir}'."; return 1; }' EXIT

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

  cd "${original_dir}" || {
    echo "Error: Could not change back to original directory '${original_dir}'."
    return 1
  }
}

# Helper function to create common HSM args array
function create_hsm_args() {
  local token="$1"
  local softhsm_conf="$2"

  echo "(
    \"--hsm_module\" \"${HSMTOOL_MODULE}\"
    \"--token\" \"${token}\"
    \"--softhsm_config\" \"${softhsm_conf}\"
    \"--hsm_pin\" \"${HSMTOOL_PIN}\"
  )"
}

if [[ "dev" == "${DEPLOY_ENV}" ]]; then
  # Create argument arrays using the helper function
  eval "SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "${SOFTHSM2_CONF_SPM}")"
  eval "OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "${SOFTHSM2_CONF_OFFLINE}")"

  # Run the HSM initialization script for SPM.
  run_hsm_init "${SPM_SKU_DIR}/spm_init.bash" "${SPM_ARGS[@]}"

  run_hsm_init "${SPM_SKU_DIR}/spm_export.bash" "${SPM_ARGS[@]}" \
    --output_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz"

  # Run the SKU initilization script in the offline HSM partition.
  # Creates root CA private key and RMA wrap/unwrap key.
  run_hsm_init "${EG_COMMON_DIR}/offline_init.bash" "${OFFLINE_ARGS[@]}"

  # Exports RMA public key and high and low security seeds from the offline HSM
  # partition.
  run_hsm_init "${EG_COMMON_DIR}/offline_export.bash" "${OFFLINE_ARGS[@]}" \
    --input_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz" \
    --output_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"

  # Generate SPM private keys.
  run_hsm_init "${EG_COMMON_DIR}/spm_sku_init.bash" "${SPM_ARGS[@]}" \
    --input_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"

  CA_KEYGEN_SCRIPTS=(
    "spm_ca_keygen.bash"
    "cr01_spm_ca_keygen.bash"
    "pi01_spm_ca_keygen.bash"
    "ti01_spm_ca_keygen.bash"
  )

  # Generate Intermediate CA private keys.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_KEYGEN_SCRIPTS[i]}" "${SPM_ARGS[@]}"
  done

  # Create CA argument arrays using the helper function with long args
  eval "CA_SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "${SOFTHSM2_CONF_SPM}")"
  eval "CA_OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "${SOFTHSM2_CONF_OFFLINE}")"
else
  # In production mode, we only perform CA CSR and signing operations.
  # Create CA argument arrays using the helper function with long args
  eval "CA_SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "")"
  eval "CA_OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "")"
fi

# Generate Root Certificate.
run_hsm_init "${EG_COMMON_DIR}/ca_root_certgen.bash" "${CA_OFFLINE_ARGS[@]}" \
  --output_tar "${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}"

CA_CERTGEN_SCRIPTS=(
  "ca_intermediate_certgen.bash"
  "cr01_ca_intermediate_certgen.bash"
  "pi01_ca_intermediate_certgen.bash"
  "ti01_ca_intermediate_certgen.bash"
)

# Export Intermediate CA CSRs from SPM HSM.
for i in "${!SKU_DIRS[@]}"; do
  run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_SPM_ARGS[@]}" \
    --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}" \
    --csr_only
done

# Endorse Intermediate CA CSRs in offline HSM.
for i in "${!SKU_DIRS[@]}"; do
  run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_OFFLINE_ARGS[@]}" \
    --input_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}:${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}" \
    --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CERTS_TAR_GZ}" \
    --sign_only
done

echo "HSM initialization complete."
