#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
readonly OUTDIR_HSM="hsm"
readonly OUTDIR_CA="ca"
readonly OUTDIR_PUB="pub"

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
}

# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"

echo "Configuring Offline HSM"
SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" "${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                     \
  --token="${SPM_HSM_TOKEN_OFFLINE}" \
  exec "01.hsm_offline.hjson"

echo "Generating CA certificates"
certgen ca_root opentitan-ca-root-v0.priv opentitan-ca-root-v0.priv
certgen ca_int_dice sival-dice-key-p256-v0.priv opentitan-ca-root-v0.priv

tar -czvf sival.tar.gz "${OUTDIR_HSM}" "${OUTDIR_CA}" "${OUTDIR_PUB}"

"${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
  exec "02.hsm_spm.hjson"
