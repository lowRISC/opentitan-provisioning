#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e


# The script must be executed from its local directory.
"${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
  exec "init.hjson"

echo "Creating test root CA certificats"
"${OPENTITAN_VAR_DIR}/bin/certgen" \
  --hsm_pw="${HSMTOOL_PIN}"        \
  --hsm_so="${HSMTOOL_MODULE}"     \
  --hsm_slot=0                     \
  --ca_key_label="KCAPriv"         \
  --ca_outfile="${OPENTITAN_VAR_DIR}/spm/certs/NuvotonTPMRootCA0200.cer"
