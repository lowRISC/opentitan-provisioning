#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Entrypoint for the simulated Windows ATE machine.
#
# Runs the Win32 ATE harness under Wine and normalizes its exit status. All
# arguments are forwarded verbatim to the harness.

set -uo pipefail

readonly EXE="${ATE_CLIENT_EXE:-ate_dll_smoke.exe}"

if [[ ! -f "${EXE}" ]]; then
  echo "ERROR: ${EXE} not found in $(pwd)." >&2
  exit 2
fi

# Wine emits unrelated driver probe noise on hosts without a GPU.
wine "${EXE}" "$@" 2> >(grep -v -E '^(TU|MESA|wine: Read access denied)' >&2)
status=$?

# Reap the wineserver so the container exits promptly instead of lingering on
# the background daemon.
wineserver --kill >/dev/null 2>&1 || true

exit "${status}"
