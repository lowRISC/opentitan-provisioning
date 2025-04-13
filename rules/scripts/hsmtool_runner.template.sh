#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 -i <input.tar.gz> -o <output.tar.gz>"
  echo "  -m <pkcs.some>     Path to the PKCS#11 module."
  echo "  -t <token>         Token name."
  echo "  -s <SoftHSMConfig> Path to the SoftHSM config file. Optional."
  echo "  -p <pin>           PIN for the token."
  echo "  -i <input.tar.gz>  Path to the input tarball."
  echo "  -w                 Execute destroy commands before initializing the assets."
  echo "  -o <output.tar.gz> Path to the output tarball."
  exit 1
}

readonly OUTDIR_HSM="hsm"
readonly OUTDIR_CA="ca"
readonly OUTDIR_PUB="pub"

readonly INIT_HJSON=@@INIT_HJSON@@
readonly DESTROY_HJSON=@@DESTROY_HJSON@@
readonly HSMTOOL_BIN_DEFAULT=@@HSMTOOL_BIN@@
readonly CERTGEN_TEMPLATES=(@@CERTGEN_TEMPLATES@@)
readonly CERTGEN_KEYS=(@@CERTGEN_KEYS@@)
readonly CERTGEN_ENDORSING_KEYS=(@@CERTGEN_ENDORSING_KEYS@@)

HSMTOOL_BIN="${HSMTOOL_BIN:-./${HSMTOOL_BIN_DEFAULT}}"

FLAGS_HSMTOOL_MODULE=""
FLAGS_HSMTOOL_TOKEN=""
FLAGS_SOFTHSM_CONFIG=""
FLAGS_HSMTOOL_PIN=""
FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""
FLAGS_WIPE=false

while getopts 'm:t:s:p:i:o:w' opt; do
  case "${opt}" in
    m)
      FLAGS_HSMTOOL_MODULE="${OPTARG}"
      ;;
    t)
      FLAGS_HSMTOOL_TOKEN="${OPTARG}"
      ;;
    s)
      FLAGS_SOFTHSM_CONFIG="${OPTARG}"
      ;;
    p)
      FLAGS_HSMTOOL_PIN="${OPTARG}"
      ;;
    i)
      FLAGS_IN_TAR="${OPTARG}"
      ;;
    o)
      FLAGS_OUT_TAR="${OPTARG}"
      ;;
    w)
      FLAGS_WIPE=true
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

if [[ ! -x "${HSMTOOL_BIN}" ]]; then
  echo "Error: HSMTOOL_BIN is not set or not executable."
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

if [[ ${#CERTGEN_TEMPLATES[@]} -ne ${#CERTGEN_KEYS[@]} ]]; then
  echo "Error: Number of certgen templates and keys do not match."
  exit 1
fi

if [[ ${#CERTGEN_TEMPLATES[@]} -ne ${#CERTGEN_ENDORSING_KEYS[@]} ]]; then
  echo "Error: Number of certgen templates and endorsing keys do not match."
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

  # Generate the CA certificate for the root CA.
  env "${certvars[@]}" \
  openssl req -new -engine pkcs11 -keyform engine \
    -config "${config_basename}.conf" \
    -out "${OUTDIR_CA}/${config_basename}.csr" \
    -key "pkcs11:pin-value=${HSMTOOL_PIN};object=${ca_key};token=${FLAGS_HSMTOOL_TOKEN}"

  env "${certvars[@]}" \
  openssl x509 -req -engine pkcs11 -keyform engine \
    -in "${OUTDIR_CA}/${config_basename}.csr" \
    -out "${OUTDIR_CA}/${config_basename}.pem" \
    -days 3650 \
    -extfile "${config_basename}.conf" \
    -extensions v3_ca \
    -signkey "pkcs11:pin-value=${HSMTOOL_PIN};object=${endorsing_key};token=${FLAGS_HSMTOOL_TOKEN}"

  rm "${OUTDIR_CA}/${config_basename}.csr"
}

# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"

echo "softhsm-config: ${FLAGS_SOFTHSM_CONFIG}"
echo "hsmtool-module: ${FLAGS_HSMTOOL_MODULE}"
echo "hsmtool-token: ${FLAGS_HSMTOOL_TOKEN}"
echo "hsmtool-bin: ${HSMTOOL_BIN}"

hsmtool_vars=()
if [[ -n "${FLAGS_SOFTHSM_CONFIG}" ]]; then
  hsmtool_vars+=(SOFTHSM2_CONF="${FLAGS_SOFTHSM_CONFIG}")
fi
hsmtool_vars+=(
  HSMTOOL_MODULE="${FLAGS_HSMTOOL_MODULE}"
  HSMTOOL_USER="user"
  HSMTOOL_TOKEN="${FLAGS_HSMTOOL_TOKEN}"
  HSMTOOL_PIN="${FLAGS_HSMTOOL_PIN}"
)

hsmtool_args=(
  "${HSMTOOL_BIN}"
  --logging=info
)

if [[ "${FLAGS_WIPE}" == true ]]; then
  echo "Running hsmtool destroy (--wipe) operation."

  read -p "Are you sure you want to run the ${DESTROY_HJSON} script? (y/n) " -n 1 -r
  echo
  if [[ ! ${REPLY} =~ ^[Yy]$ ]]; then
    echo "Aborting destroy operation."
    exit 1
  fi

  env "${hsmtool_vars[@]}" "${hsmtool_args[@]}" exec "${DESTROY_HJSON}"
fi

echo "Running hsmtool"
env "${hsmtool_vars[@]}" "${hsmtool_args[@]}" exec "${INIT_HJSON}"

for i in "${!CERTGEN_TEMPLATES[@]}"; do
  template="${CERTGEN_TEMPLATES[$i]}"
  key="${CERTGEN_KEYS[$i]}"
  endorsing_key="${CERTGEN_ENDORSING_KEYS[$i]}"

  echo "Generating certificate for ${template}"
  certgen "${template}" "${key}" "${endorsing_key}"
done

if [[ -n "${FLAGS_OUT_TAR}" ]]; then
  echo "Exporting HSM data to ${FLAGS_OUT_TAR}"
  tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"
  rm -rf "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"
fi
