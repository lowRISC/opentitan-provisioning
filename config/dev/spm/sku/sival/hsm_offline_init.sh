#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 -i <input.tar.gz> -o <output.tar.gz>"
  echo "  -i <input.tar.gz>  Path to the input tarball."
  echo "  -o <output.tar.gz> Path to the output tarball."
  exit 1
}

readonly OUTDIR_HSM="hsm"
readonly OUTDIR_CA="ca"
readonly OUTDIR_PUB="pub"

FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""

while getopts 'i:o:' opt; do
  case "${opt}" in
    i)
      FLAGS_IN_TAR="${OPTARG}"
      ;;
    o)
      FLAGS_OUT_TAR="${OPTARG}"
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

if [[ ! -x "${HSMTOOL_BIN}" ]]; then
  echo "Error: HSMTOOL_BIN is not set or not executable."
  exit 1
fi

if [[ -z "${FLAGS_IN_TAR}" ]]; then
  echo "Error: Input tarball not specified."
  exit 1
fi
if [[ "${FLAGS_IN_TAR}" != *.tar.gz  ]]; then
  echo "Error: Input tarball must have .tar.gz extension."
  exit 1
fi
if [[ -z "${FLAGS_OUT_TAR}" ]]; then
  echo "Error: Output tarball not specified."
  exit 1
fi
if [[ "${FLAGS_OUT_TAR}" != *.tar.gz  ]]; then
  echo "Error: Output tarball must have .tar.gz extension."
  exit 1
fi

tar -xzf "${FLAGS_IN_TAR}"

# certgen generates a certificate for the given config file and signs it with
# the given CA key.
certgen () {
  config_basename=$1
  ca_key=$2
  endorsing_key=$3

  # Generate the CA certificate for the root CA.
  SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" \
  PKCS11_MODULE_PATH="${HSMTOOL_MODULE}" \
  openssl req -new -engine pkcs11 -keyform engine \
    -config "${config_basename}.conf" \
    -out "${OUTDIR_CA}/${config_basename}.csr" \
    -key "pkcs11:pin-value=${HSMTOOL_PIN};object=${ca_key}"

  SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" \
  PKCS11_MODULE_PATH="${HSMTOOL_MODULE}" \
  openssl x509 -req -engine pkcs11 -keyform engine \
    -in "${OUTDIR_CA}/${config_basename}.csr" \
    -out "${OUTDIR_CA}/${config_basename}.pem" \
    -days 3650 \
    -extfile "${config_basename}.conf" \
    -extensions v3_ca \
    -signkey "pkcs11:pin-value=${HSMTOOL_PIN};object=${endorsing_key}"

  rm "${OUTDIR_CA}/${config_basename}.csr"
}

# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"

echo "Configuring Offline HSM"
SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" "${HSMTOOL_BIN}" \
  --logging=info                     \
  --token="${SPM_HSM_TOKEN_OFFLINE}" \
  exec "01.hsm_offline.hjson"

echo "Generating CA certificates"
certgen ca_root opentitan-ca-root-v0.priv opentitan-ca-root-v0.priv
certgen ca_int_dice sival-dice-key-p256-v0.priv opentitan-ca-root-v0.priv

tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"
rm -rf "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"
