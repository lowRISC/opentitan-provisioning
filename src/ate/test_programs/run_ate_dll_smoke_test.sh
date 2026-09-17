#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Hermetic Win32 ATE DLL smoke test.
#
# Installs the Windows bundle into the simulated Windows ATE machine container
# and calls `CreateClient()` there in both insecure and mTLS mode. No
# provisioning appliance is needed: channel creation is lazy, so this exercises
# gRPC channel construction only -- which is where the 32-bit MinGW toolchain
# has been observed to miscompile gRPC (0xC0000005). The container runs with
# networking disabled to keep the test hermetic. For a test that also performs
# RPCs against a live PA, see tests/run_ate_dll_test.sh.

set -euo pipefail

source util/ate_client_container.sh

readonly OPENSSL_BIN="${OPENSSL:-openssl}"

ate_client_require_podman
if ! command -v "${OPENSSL_BIN}" >/dev/null 2>&1; then
  echo "ERROR: '${OPENSSL_BIN}' not found in PATH."
  exit 1
fi

readonly SMOKE_EXE="${SMOKE_EXE:?SMOKE_EXE must point at ate_dll_smoke.exe}"
readonly ATE_DLL="${ATE_DLL:?ATE_DLL must point at ate.dll}"

readonly REPO_TOP="${PWD}"
readonly WORK_DIR="${TEST_TMPDIR:-$(mktemp -d)}/ate_dll_smoke"
readonly CERTS_DIR="${WORK_DIR}/certs"

ate_client_ensure_base_image "${REPO_TOP}"

ate_client_stage_bundle "${WORK_DIR}" "${SMOKE_EXE}" "${ATE_DLL}"
ate_client_build_image "${REPO_TOP}" "${WORK_DIR}"

# Throwaway credentials. They only need to parse: no handshake is performed.
echo "Generating test credentials..."
mkdir -p "${CERTS_DIR}"
"${OPENSSL_BIN}" req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "${CERTS_DIR}/ca-key.pem" \
  -out "${CERTS_DIR}/ca-cert.pem" \
  -subj "/CN=ate-dll-smoke-ca" 2>/dev/null
"${OPENSSL_BIN}" req -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/ate-client-key.pem" \
  -out "${CERTS_DIR}/ate-client.csr" \
  -subj "/CN=ate-dll-smoke-client" 2>/dev/null
"${OPENSSL_BIN}" x509 -req -days 1 \
  -in "${CERTS_DIR}/ate-client.csr" \
  -CA "${CERTS_DIR}/ca-cert.pem" \
  -CAkey "${CERTS_DIR}/ca-key.pem" \
  -CAcreateserial \
  -out "${CERTS_DIR}/ate-client-cert.pem" 2>/dev/null
rm -f "${CERTS_DIR}/ate-client.csr"

failures=0
run_case() {
  local name="$1"
  shift
  echo "=============================================================="
  echo "== ${name}"
  echo "=============================================================="
  local status=0
  ate_client_run "none" "${CERTS_DIR}" "$@" || status=$?
  ate_client_report_status "${name}" "${status}" || failures=$((failures + 1))
}

run_case "insecure" --target=localhost:5000
run_case "mtls" --target=localhost:5000 --mtls \
  --cert=certs/ate-client-cert.pem \
  --key=certs/ate-client-key.pem \
  --ca=certs/ca-cert.pem

if [[ "${failures}" -ne 0 ]]; then
  echo "${failures} case(s) failed."
  exit 1
fi
echo "All cases passed."
