#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
"${OPENTITAN_VAR_DIR}/bin/hsmtool" \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
   exec "hsm_spm_init.hjson"
