#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 --input_tar <input.tar.gz> --output_tar <output.tar.gz>"
  echo "  --hsm_module <pkcs.some>     Path to the PKCS#11 module."
  echo "  --token <token>              Token name."
  echo "  --softhsm_config <config>    Path to the SoftHSM config file. Optional."
  echo "  --hsm_pin <pin>              PIN for the token."
  echo "  --input_tar <input.tar.gz>   Path to the input tarball."
  echo "  --output_tar <output.tar.gz> Path to the output tarball."
  echo "  --csr_only                   Only export CSRs, do not sign them."
  echo "  --sign_only                  Only sign certificates, skip CSR generation."
  echo "  --help                       Show this help message."
  exit 1
}

readonly OUTDIR_CA="ca"

readonly CERTGEN_TEMPLATES=(@@CERTGEN_TEMPLATES@@)
readonly CERTGEN_KEYS=(@@CERTGEN_KEYS@@)
readonly CERTGEN_ENDORSING_KEYS=(@@CERTGEN_ENDORSING_KEYS@@)

FLAGS_HSMTOOL_MODULE=""
FLAGS_HSMTOOL_TOKEN=""
FLAGS_SOFTHSM_CONFIG=""
FLAGS_HSMTOOL_PIN=""
FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""
FLAGS_CSR_ONLY=false
FLAGS_SIGN_ONLY=false

LONGOPTS="hsm_module:,token:,softhsm_config:,hsm_pin:,input_tar:,output_tar:,csr_only,sign_only,help"
OPTS=$(getopt -o "" --long "${LONGOPTS}" -n "$0" -- "$@")

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

eval set -- "$OPTS"

while true; do
  case "$1" in
    --hsm_module)
      FLAGS_HSMTOOL_MODULE="$2"
      shift 2
      ;;
    --token)
      FLAGS_HSMTOOL_TOKEN="$2"
      shift 2
      ;;
    --softhsm_config)
      FLAGS_SOFTHSM_CONFIG="$2"
      shift 2
      ;;
    --hsm_pin)
      FLAGS_HSMTOOL_PIN="$2"
      shift 2
      ;;
    --input_tar)
      FLAGS_IN_TAR="$2"
      shift 2
      ;;
    --output_tar)
      FLAGS_OUT_TAR="$2"
      shift 2
      ;;
    --csr_only)
      FLAGS_CSR_ONLY=true
      shift
      ;;
    --sign_only)
      FLAGS_SIGN_ONLY=true
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

if [[ -z "${FLAGS_HSMTOOL_MODULE}" ]]; then
  echo "Error: -m HSMTOOL_MODULE is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_TOKEN}" ]]; then
  echo "Error: -t HSMTOOL_TOKEN is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_PIN}" ]]; then
  echo "Error: -p HSMTOOL_PIN is not set."
  exit 1
fi

if [[ ${#CERTGEN_TEMPLATES[@]} -ne ${#CERTGEN_ENDORSING_KEYS[@]} ]]; then
  echo "Error: Number of certgen templates and endorsing keys do not match."
  exit 1
fi

if [[ "${FLAGS_CSR_ONLY}" == true ]] && [[ "${FLAGS_SIGN_ONLY}" == true ]]; then
  echo "Error: --csr_only and --sign_only cannot be used together."
  exit 1
fi

if [[ -n "${FLAGS_IN_TAR}" && "${FLAGS_IN_TAR}" != *.tar.gz  ]]; then
  echo "Error: Input tarball must have .tar.gz extension."
  exit 1
fi

if [[ -n "${FLAGS_OUT_TAR}" && "${FLAGS_OUT_TAR}" != *.tar.gz  ]]; then
  echo "Error: Output tarball must have .tar.gz extension."
  exit 1
fi

if [[ -n "${FLAGS_IN_TAR}" ]]; then
  if [[ ! -f "${FLAGS_IN_TAR}" ]]; then
    echo "Error: Input tarball does not exist."
    exit 1
  fi
  echo "Extracting input tarball ${FLAGS_IN_TAR}"
  tar -xzf "${FLAGS_IN_TAR}"
fi


# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_CA}"

# If the GEM engine is used, we need to initialize a session with the HSM.
# The following variable is used to track if the session has been initialized.
# The close_gem_engine_session function will be called on exit to close the session.
CA_GEM_ENGINE_INIT=false
close_gem_engine_session () {
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ] && [ "${CA_GEM_ENGINE_INIT}" == true ]; then
    echo "Closing Gem engine session."
    sautil -s "${OTPROV_GEM_SLOT_CERT_OPS}" -i 10:11 -c
    CA_GEM_ENGINE_INIT=false
  fi
}
trap close_gem_engine_session EXIT

if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
  if ! command -v "sautil" &> /dev/null; then
    echo "Error: Required command 'sautil' is not installed or not in your PATH." >&2
    exit 1
  fi

  if [[ -z "${OTPROV_GEM_SLOT_CERT_OPS}" ]]; then
    echo "Error: -p OTPROV_GEM_SLOT_CERT_OPS is not set."
    exit 1
  fi

  # Initialize a session with the HSM using the sautil command. Provided by
  # the Gem engine.
  # The user is expected to set this environment variable to set the correct
  # HSM slot for certificate operations.
  sautil -s "${OTPROV_GEM_SLOT_CERT_OPS}" -i 10:11 -o -p "${FLAGS_HSMTOOL_PIN}"
  CA_GEM_ENGINE_INIT=true
fi


# certgen generates a certificate for the given config file and signs it with
# the given CA key.
certgen () {
  config_basename="${1%.conf}"
  ca_key="${2}"
  endorsing_key="${3}"

  certvars=()
  if [[ -n "${FLAGS_SOFTHSM_CONFIG}" ]]; then
    certvars+=(SOFTHSM2_CONF="${FLAGS_SOFTHSM_CONFIG}")
  fi
  certvars+=(
    PKCS11_MODULE_PATH="${FLAGS_HSMTOOL_MODULE}"
  )

  ENGINE="pkcs11"
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
    ENGINE="gem"
  fi

  KEY="pkcs11:pin-value=${FLAGS_HSMTOOL_PIN};object=${ca_key};token=${FLAGS_HSMTOOL_TOKEN}"
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
    KEY="${ca_key}"
  fi

  CONFIG_FILE="${config_basename}.conf"
  CSR_FILE="${OUTDIR_CA}/${ca_key}.csr"
  CERT_FILE="${OUTDIR_CA}/${ca_key}.pem"



  if [[ "${FLAGS_SIGN_ONLY}" == false ]]; then
    # Generate a CSR for the CA key. This can be either a root CA or an
    # intermediate CA.
    echo "Generating CSR for ${ca_key}"
    env "${certvars[@]}" \
    openssl req -new -engine "${ENGINE}" -keyform engine \
        -config "${CONFIG_FILE}" \
        -out "${CSR_FILE}" \
        -key "${KEY}"
  else
    # Running in sign only mode means that the CSR is already present in the
    # input tarball and/or ca directory. Only need to check if the CSR file
    # exists.
    if [[ ! -f "${CSR_FILE}" ]]; then
      echo "Error: CSR file ${CSR_FILE} does not exist."
      exit 1
    fi
  fi

  # Skip certificate signing if we are only generating CSRs.
  if [[ "${FLAGS_CSR_ONLY}" == true ]]; then
    return
  fi

  ENDORSING_KEY="pkcs11:pin-value=${HSMTOOL_PIN};object=${endorsing_key};token=${FLAGS_HSMTOOL_TOKEN}"
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
    ENDORSING_KEY="${endorsing_key}"
  fi

  if [[ "${ca_key}" == "${endorsing_key}" ]]; then
    echo "Generating root CA certificate for ${ca_key}"
    env "${certvars[@]}" \
    openssl x509 -req -engine "${ENGINE}" -keyform engine \
      -in "${CSR_FILE}" \
      -out "${CERT_FILE}" \
      -days 7300 \
      -extfile "${CONFIG_FILE}" \
      -extensions v3_ca \
      -signkey "${ENDORSING_KEY}"
  else
    echo "Generating certificate for ${ca_key} signed by ${endorsing_key}"

    CA_ENDORSING_CERT_FILE="${OUTDIR_CA}/${endorsing_key}.pem"
    if [[ ! -f "${CA_ENDORSING_CERT_FILE}" ]]; then
      echo "Error: CA endorsing certificate file ${CA_ENDORSING_CERT_FILE} does not exist."
      exit 1
    fi

    env "${certvars[@]}" \
    openssl x509 -req -engine "${ENGINE}" -keyform engine \
      -in "${CSR_FILE}" \
      -out "${CERT_FILE}" \
      -days 7300 \
      -extfile "${CONFIG_FILE}" \
      -extensions v3_ca \
      -CA "${CA_ENDORSING_CERT_FILE}" \
      -CAkeyform engine \
      -CAkey "${ENDORSING_KEY}"
  fi

  echo "Converting certificate for ${ca_key} to DER"
  openssl x509 -in "${CERT_FILE}" -outform DER -out "${OUTDIR_CA}/${ca_key}.der"
}

for i in "${!CERTGEN_TEMPLATES[@]}"; do
  template="${CERTGEN_TEMPLATES[$i]}"
  key="${CERTGEN_KEYS[$i]}"
  endorsing_key="${CERTGEN_ENDORSING_KEYS[$i]}"

  echo "Generating certificate for ${template}"
  certgen "${template}" "${key}" "${endorsing_key}"
done

if [[ -n "${FLAGS_OUT_TAR}" ]]; then
  echo "Exporting HSM data to ${FLAGS_OUT_TAR}"
  tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_CA}"
fi

