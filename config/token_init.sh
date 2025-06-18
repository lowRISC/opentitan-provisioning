#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

usage () {
  echo "Usage: $0 --action <action> [--sku <sku>]..."
  echo "  --action <action>            Action to perform. Required."
  echo "  --sku <sku>                  SKU to process. Can be specified multiple times. Required for some actions."
  echo "  --wipe                       Wipe the SPM wrapping key before exporting secrets from the offline HSM."
  echo "  --help                       Show this help message."

  echo "Available actions:"
  echo "  - spm-init: Initialize the SPM HSM with a new identity key and wrapping key."
  echo "  - offline-common-init: Initialize the offline HSM with secrets and CA private key."
  echo "  - offline-common-export: Export the offline HSM secrets."
  echo "  - spm-sku-init: Initialize the SPM with all SKU private keys."
  echo "  - spm-sku-csr: Generate the CSRs for all SKUs."
  echo "  - offline-sku-certgen: Endorse the CSRs for all SKUs."
  echo "  - offline-ca-root-certgen: Generate the root certificate."

  echo "Available SKUs:"
  echo "  - sival: Sival SKU"
  echo "  - cr: CR SKU"
  echo "  - pi: PI SKU"
  echo "  - ti: TI SKU"

  exit 1
}

FLAG_ACTION=""
FlAGS_WIPE=""
FLAGS_SKUS_ARRAY=()

LONGOPTS="action:,sku:,wipe,help"
OPTS=$(getopt -o "" --long "${LONGOPTS}" -n "$0" -- "$@")

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

eval set -- ${OPTS}

while true; do
  case "$1" in
    --action)
      # Strip quotes that getopt may add.
      FLAG_ACTION="${2//\'/}"
      shift 2
      ;;
    --sku)
      # Strip quotes that getopt may add.
      sku_val="${2//\'/}"
      FLAGS_SKUS_ARRAY+=("$sku_val")
      shift 2
      ;;
    --wipe)
      FlAGS_WIPE="--wipe"
      shift
      ;;
    --help)
      usage
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

if [[ "$#" -gt 0 ]]; then
  echo "Unexpected arguments:" "$@" >&2
  exit 1
fi

if [[ -z "${DEPLOY_ENV}" ]]; then
  echo "Error: DEPLOY_ENV environment variable is not set."
  exit 1
fi

if [[ -z "${OPENTITAN_VAR_DIR}" ]]; then
  echo "Error: OPENTITAN_VAR_DIR environment variable is not set."
  echo "Please set the OPENTITAN_VAR_DIR environment variable to the path of the OpenTitan variable directory."
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

if [[ ! -d "${SPM_SKU_DIR}" ]]; then
  echo "Error: SPM SKU directory '${SPM_SKU_DIR}' does not exist."
  exit 1
fi

# Common HSM archive filenames
HSM_CA_INTERMEDIATE_CSR_TAR_GZ="hsm_ca_intermediate_csr.tar.gz"
HSM_CA_INTERMEDIATE_CERTS_TAR_GZ="hsm_ca_intermediate_certs.tar.gz"
HSM_CA_ROOT_CERTS_TAR_GZ="hsm_ca_root_certs.tar.gz"

declare -A SKU_TO_DIR=(
  ["sival"]="${SIVAL_DIR}"
  ["cr01"]="${EG_CR_DIR}"
  ["pi01"]="${EG_PI_DIR}"
  ["ti01"]="${EG_TI_DIR}"
)

declare -A SKU_TO_KEYGEN_SCRIPT=(
  ["sival"]="spm_ca_keygen.bash"
  ["cr01"]="cr01_spm_ca_keygen.bash"
  ["pi01"]="pi01_spm_ca_keygen.bash"
  ["ti01"]="ti01_spm_ca_keygen.bash"
)

declare -A SKU_TO_CERTGEN_SCRIPT=(
  ["sival"]="ca_intermediate_certgen.bash"
  ["cr01"]="cr01_ca_intermediate_certgen.bash"
  ["pi01"]="pi01_ca_intermediate_certgen.bash"
  ["ti01"]="ti01_ca_intermediate_certgen.bash"
)

SKU_DIRS=()
CA_KEYGEN_SCRIPTS=()
CA_CERTGEN_SCRIPTS=()
for sku in "${FLAGS_SKUS_ARRAY[@]}"; do
  if [[ -n "${SKU_TO_DIR[$sku]}" ]]; then
    SKU_DIRS+=("${SKU_TO_DIR[$sku]}")
  fi
  if [[ -n "${SKU_TO_KEYGEN_SCRIPT[$sku]}" ]]; then
    CA_KEYGEN_SCRIPTS+=("${SKU_TO_KEYGEN_SCRIPT[$sku]}")
  fi
  if [[ -n "${SKU_TO_CERTGEN_SCRIPT[$sku]}" ]]; then
    CA_CERTGEN_SCRIPTS+=("${SKU_TO_CERTGEN_SCRIPT[$sku]}")
  fi
done

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

  # Create CA argument arrays using the helper function with long args
  eval "CA_SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "${SOFTHSM2_CONF_SPM}")"
  eval "CA_OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "${SOFTHSM2_CONF_OFFLINE}")"
else
  # Create argument arrays using the helper function
  eval "SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "")"
  eval "OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "")"

  # Create CA argument arrays using the helper function with long args
  eval "CA_SPM_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_SPM}" "")"
  eval "CA_OFFLINE_ARGS=$(create_hsm_args "${SPM_HSM_TOKEN_OFFLINE}" "")"
fi

if [[ "${FLAG_ACTION}" == "spm-init" ]]; then
  # Run the HSM initialization script for SPM.
  run_hsm_init "${SPM_SKU_DIR}/spm_init.bash" "${SPM_ARGS[@]}"

  run_hsm_init "${SPM_SKU_DIR}/spm_export.bash" "${SPM_ARGS[@]}" \
    --output_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz"
fi

if [[ "${FLAG_ACTION}" == "offline-common-init" ]]; then
  # Run the SKU initilization script in the offline HSM partition.
  # Creates root CA private key and RMA wrap/unwrap key.
  run_hsm_init "${EG_COMMON_DIR}/offline_init.bash" "${OFFLINE_ARGS[@]}"
fi

if [[ "${FLAG_ACTION}" == "offline-common-export" ]]; then
  # Exports RMA public key and high and low security seeds from the offline HSM
  # partition. Always run the command with --wipe to ensure the SPM wrapping key
  # is destroyed if it exists.
  run_hsm_init "${EG_COMMON_DIR}/offline_export.bash" "${OFFLINE_ARGS[@]}" ${FlAGS_WIPE} \
    --input_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz" \
    --output_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"
fi

if [[ "${FLAG_ACTION}" == "spm-sku-init" ]]; then
  # Generate SPM private keys.
  run_hsm_init "${EG_COMMON_DIR}/spm_sku_init.bash" "${SPM_ARGS[@]}" \
    --input_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"

  # Generate Intermediate CA private keys.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_KEYGEN_SCRIPTS[i]}" "${SPM_ARGS[@]}"
  done
fi

if [[ "${FLAG_ACTION}" == "offline-ca-root-certgen" ]]; then
  # Generate Root Certificate.
  run_hsm_init "${EG_COMMON_DIR}/ca_root_certgen.bash" "${CA_OFFLINE_ARGS[@]}" \
    --output_tar "${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}"
fi

if [[ "${FLAG_ACTION}" == "spm-sku-csr" ]]; then
  # Export Intermediate CA CSRs from SPM HSM.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_SPM_ARGS[@]}" \
      --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}" \
      --csr_only
  done
fi

if [[ "${FLAG_ACTION}" == "offline-sku-certgen" ]]; then
  # Endorse Intermediate CA CSRs in offline HSM.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_OFFLINE_ARGS[@]}" \
      --input_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}:${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}" \
      --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CERTS_TAR_GZ}" \
      --sign_only
  done
fi

echo "HSM initialization complete."
