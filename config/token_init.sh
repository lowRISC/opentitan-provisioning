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
  echo "  --show                       Show the HSM contents."
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
  echo "  - test_mldsa: Test MLDSA SKU"
  echo "  - cr: CR SKU"
  echo "  - pi: PI SKU"
  echo "  - ti: TI SKU"

  exit 1
}

FLAG_ACTION=""
FlAGS_WIPE=""
FLAGS_SHOW=""
FLAGS_SKUS_ARRAY=()

LONGOPTS="action:,sku:,wipe,show,help"
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
    --show)
      FLAGS_SHOW="--show"
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

if [[ -z "${FLAG_ACTION}" ]]; then
  echo "Error: --action is required." >&2
  usage
fi

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
TEST_MLDSA_DIR="${SPM_SKU_DIR}/test_mldsa"
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
  ["test_mldsa"]="${TEST_MLDSA_DIR}"
  ["cr01"]="${EG_CR_DIR}"
  ["pi01"]="${EG_PI_DIR}"
  ["ti01"]="${EG_TI_DIR}"
)

declare -A SKU_TO_KEYGEN_SCRIPT=(
  ["sival"]="spm_ca_keygen.bash"
  ["test_mldsa"]="spm_ca_keygen.bash"
  ["cr01"]="cr01_spm_ca_keygen.bash"
  ["pi01"]="pi01_spm_ca_keygen.bash"
  ["ti01"]="ti01_spm_ca_keygen.bash"
)

declare -A SKU_TO_CERTGEN_SCRIPT=(
  ["sival"]="ca_intermediate_certgen.bash"
  ["test_mldsa"]="ca_intermediate_certgen.bash"
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

  trap 'cd "${original_dir}" || { echo "Error: Could not change back to original directory ${original_dir}."; return 1; }' EXIT

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

  trap - EXIT
}

function action_spm_init() {
  run_hsm_init "${SPM_SKU_DIR}/spm_init.bash" "${SPM_ARGS[@]}" ${FLAGS_SHOW}
  if [[ -n "${FLAGS_SHOW}" ]]; then
    exit 0
  fi
  # Run the HSM initialization script for SPM.
  run_hsm_init "${SPM_SKU_DIR}/spm_export.bash" "${SPM_ARGS[@]}" \
    --output_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz"
}

function action_offline_common_init() {
  # Run the SKU initilization script in the offline HSM partition.
  # Creates root CA private key and RMA wrap/unwrap key.
  run_hsm_init "${EG_COMMON_DIR}/offline_init.bash" "${OFFLINE_ARGS[@]}" ${FLAGS_SHOW}
}

function action_offline_common_export() {
  if [[ -n "${FLAGS_SHOW}" ]]; then
    echo "Action 'offline-common-export' does not support --show." >&2
    exit 1
  fi
  # Exports RMA public key and high and low security seeds from the offline HSM
  # partition. Always run the command with --wipe to ensure the SPM wrapping key
  # is destroyed if it exists.
  run_hsm_init "${EG_COMMON_DIR}/offline_export.bash" "${OFFLINE_ARGS[@]}" ${FlAGS_WIPE} \
    --input_tar "${SPM_SKU_DIR}/spm_hsm_init.tar.gz" \
    --output_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"
}

function action_spm_sku_init() {
  if [[ -n "${FLAGS_SHOW}" ]]; then
    run_hsm_init "${EG_COMMON_DIR}/spm_sku_init.bash" "${SPM_ARGS[@]}" ${FLAGS_SHOW}
    for i in "${!SKU_DIRS[@]}"; do
      run_hsm_init "${SKU_DIRS[i]}/${CA_KEYGEN_SCRIPTS[i]}" "${SPM_ARGS[@]}" ${FLAGS_SHOW}
    done
  else
    # Generate SPM private keys.
    run_hsm_init "${EG_COMMON_DIR}/spm_sku_init.bash" "${SPM_ARGS[@]}" \
      --input_tar "${EG_COMMON_DIR}/hsm_offline_export.tar.gz"

    # Generate Intermediate CA private keys.
    for i in "${!SKU_DIRS[@]}"; do
      run_hsm_init "${SKU_DIRS[i]}/${CA_KEYGEN_SCRIPTS[i]}" "${SPM_ARGS[@]}"
    done
  fi
}

function action_offline_ca_root_certgen() {
  if [[ -n "${FLAGS_SHOW}" ]]; then
    echo "Action 'offline-ca-root-certgen' does not support --show." >&2
    exit 1
  fi
  # Generate Root Certificate.
  run_hsm_init "${EG_COMMON_DIR}/ca_root_certgen.bash" "${CA_OFFLINE_ARGS[@]}" \
    --output_tar "${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}"
}

function action_spm_sku_csr() {
  if [[ -n "${FLAGS_SHOW}" ]]; then
    echo "Action 'spm-sku-csr' does not support --show." >&2
    exit 1
  fi
  # Export Intermediate CA CSRs from SPM HSM.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_SPM_ARGS[@]}" \
      --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}" \
      --csr_only
  done
}

function action_offline_sku_certgen() {
  if [[ -n "${FLAGS_SHOW}" ]]; then
    echo "Action 'offline-sku-certgen' does not support --show." >&2
    exit 1
  fi
  # Endorse Intermediate CA CSRs in offline HSM.
  for i in "${!SKU_DIRS[@]}"; do
    run_hsm_init "${SKU_DIRS[i]}/${CA_CERTGEN_SCRIPTS[i]}" "${CA_OFFLINE_ARGS[@]}" \
      --input_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CSR_TAR_GZ}:${EG_COMMON_DIR}/${HSM_CA_ROOT_CERTS_TAR_GZ}" \
      --output_tar "${SKU_DIRS[i]}/${HSM_CA_INTERMEDIATE_CERTS_TAR_GZ}" \
      --sign_only
  done
}

if [[ "dev" == "${DEPLOY_ENV}" ]]; then
  spm_softhsm_conf="${SOFTHSM2_CONF_SPM}"
  offline_softhsm_conf="${SOFTHSM2_CONF_OFFLINE}"
else
  spm_softhsm_conf=""
  offline_softhsm_conf=""
fi

SPM_ARGS=(
  "--hsm_module" "${HSMTOOL_MODULE}"
  "--token" "${SPM_HSM_TOKEN_SPM}"
  "--softhsm_config" "${spm_softhsm_conf}"
  "--hsm_pin" "${HSMTOOL_PIN}"
)
OFFLINE_ARGS=(
  "--hsm_module" "${HSMTOOL_MODULE}"
  "--token" "${SPM_HSM_TOKEN_OFFLINE}"
  "--softhsm_config" "${offline_softhsm_conf}"
  "--hsm_pin" "${HSMTOOL_PIN}"
)
CA_SPM_ARGS=("${SPM_ARGS[@]}")
CA_OFFLINE_ARGS=("${OFFLINE_ARGS[@]}")

case "${FLAG_ACTION}" in
  spm-init)
    action_spm_init
    ;;
  offline-common-init)
    action_offline_common_init
    ;;
  offline-common-export)
    action_offline_common_export
    ;;
  spm-sku-init)
    action_spm_sku_init
    ;;
  offline-ca-root-certgen)
    action_offline_ca_root_certgen
    ;;
  spm-sku-csr)
    action_spm_sku_csr
    ;;
  offline-sku-certgen)
    action_offline_sku_certgen
    ;;
  *)
    echo "Error: Invalid action '${FLAG_ACTION}'." >&2
    usage
    ;;
esac

echo "HSM initialization complete."
