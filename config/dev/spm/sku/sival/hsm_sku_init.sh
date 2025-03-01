#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" "${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                     \
  --token="${SPM_HSM_TOKEN_OFFLINE}" \
  exec "01.hsm_offline.hjson"

"${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
  exec "02.hsm_spm.hjson"
