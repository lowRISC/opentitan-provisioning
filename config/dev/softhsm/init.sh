#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
set -e

usage() {
    echo >&2 "ERROR: $1"
    echo >&2 ""
    echo >&2 "Usage: $0 <config-dir> <softhsm-dir> <outdir>"
    exit 1
}

if [ $# != 3 ]; then
    usage "Unexpected number of arguments"
fi

print_message() {
    # Print messages in red for better visibility.
    echo -e "\033[0;32m${1}\033[0m"
}

readonly CONFIG_DIR=$1
readonly SOFT_HSM2=$2
export OPENTITAN_VAR_DIR=$3

readonly TEST_SKU_KEYS_DIR="${CONFIG_DIR}/softhsm/keys"
readonly MOD_PATH="${SOFT_HSM2}/lib/softhsm/libsofthsm2.so"

readonly SOFTHSM2_UTIL="${SOFT_HSM2}/bin/softhsm2-util --module=${MOD_PATH}"

# Some environment variables are used to configure the SPM server and kept in a
# separate .env file.
source "${CONFIG_DIR}/env/spm.env"

print_message "Using OPENTITAN_VAR_DIR=${OPENTITAN_VAR_DIR}"

if [ ! -d "${OPENTITAN_VAR_DIR}" ]; then
    echo "Creating config directory: ${OPENTITAN_VAR_DIR}. This requires sudo."
    sudo mkdir -p "${OPENTITAN_VAR_DIR}"
    sudo chown "${USER}" "${OPENTITAN_VAR_DIR}"
fi

readonly SOFTHSM2_CFG_DIR="${SOFTHSM2_CONF%/*}"
print_message "Using SOFTHSM2_CFG_DIR=${SOFTHSM2_CFG_DIR}"


# Remove the configuration unconditionally to avoid running into state issues.
if [ -d "${SOFTHSM2_CFG_DIR}" ]; then rm -rf "${SOFTHSM2_CFG_DIR}"; fi
mkdir -p "${SOFTHSM2_CFG_DIR}/tokens"

cat <<EOCFG > "${SOFTHSM2_CONF}"
directories.tokendir = ${SOFTHSM2_CFG_DIR}/tokens
objectstore.backend = file
objectstore.umask = 0077

log.level = DEBUG
slots.removable = false
slots.mechanisms = ALL
library.reset_on_fork = false
EOCFG

print_message "Initializing SoftHSM"

${SOFTHSM2_UTIL} --init-token --slot=0 --so-pin=${SPM_HSM_PIN_ADMIN} \
    --label="${SPM_HSM_TOKEN_LABEL}" --pin=${SPM_HSM_PIN_USER}

${SOFTHSM2_UTIL} --show-slots

print_message "Execute the following command before launching the spm service:"
print_message "export SOFTHSM2_CONF=${SOFTHSM2_CONF}"
print_message "SoftHSM configuration result: PASS!"
