#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Windows ATE client integration test.
#
# This is the Win32 counterpart of `tests/run_tls_test.sh`. Instead of the
# native Linux client, it drives the *shipped* `ate.dll` from a container that
# stands in for a Windows ATE machine: the DLL is installed into a Wine image
# and reaches the live Provisioning Appliance from its own network namespace,
# over a real interface, using the same deployment credentials.
#
# It covers what no Linux-side test can: that the cross-compiled artifact we
# hand to ATE vendors actually runs. The 32-bit MinGW toolchain has miscompiled
# gRPC's channel setup in the past, which is invisible to a cross-compile-only
# CI.

set -e

# Explicitly enable job control so that we can run the SPM server
# in the background and still be able to run other commands in parallel.
set -m

# Ensure we are running from the repository root
cd "$(dirname "$0")/.."

source util/ate_client_container.sh

ate_client_require_podman

# The ATE container reaches the appliance through podman's host alias rather
# than over loopback. Naming it here (before the deployment generates
# certificates) puts it in the PA certificate's SAN list, so TLS hostname
# verification succeeds. `OTPROV_DNS_PA` feeds only that SAN; host-side clients
# keep working through the unchanged `IP.1 = ${OTPROV_IP_PA}` entry.
readonly ATE_CLIENT_PA_HOST="host.containers.internal"
export OTPROV_DNS_PA="${ATE_CLIENT_PA_HOST}"

# Build and deploy the provisioning infrastructure.
source util/integration_test_setup.sh

# Dump PA logs on failure
dump_pa_logs() {
  echo "----------------------------------------------------------------"
  echo "Dumping PA logs (provapp-paserver-1)..."
  podman logs provapp-paserver-1
  echo "----------------------------------------------------------------"
}
trap dump_pa_logs ERR

echo "Building Win32 ATE client artifacts ..."
bazelisk build //src/ate:ate //src/ate/test_programs:ate_dll_smoke

# Enabled only from here on: the deployment scripts sourced above are not
# written with pipefail in mind.
set -o pipefail

# `cquery --output=files` reports workspace-relative paths for local artifacts
# but output-base-relative paths for external repositories.
OUTPUT_BASE="$(bazelisk info output_base)"
WORKSPACE_ROOT="${PWD}"
artifact_path() {
  if [[ "$1" == external/* ]]; then
    echo "${OUTPUT_BASE}/$1"
  else
    echo "${WORKSPACE_ROOT}/$1"
  fi
}

# Resolves a single-output target to an absolute path. The query output is
# assigned to a variable first so that a cquery failure is fatal: inside a
# pipeline or a process substitution its exit status would be discarded and we
# would carry on with an empty path, failing much later and less obviously.
resolve_artifact() {
  local label="$1"
  local files
  files="$(bazelisk cquery --output=files "${label}")"
  if [[ -z "${files}" ]]; then
    echo "ERROR: cquery returned no output files for ${label}." >&2
    return 1
  fi
  artifact_path "$(echo "${files}" | tail -n 1)"
}

ATE_DLL="$(resolve_artifact //src/ate:ate)"
SMOKE_EXE="$(resolve_artifact //src/ate/test_programs:ate_dll_smoke)"

# Install the freshly built bundle into the ATE machine image.
WORK_DIR="${OPENTITAN_VAR_DIR}/ate_dll_container"
ate_client_ensure_base_image "${WORKSPACE_ROOT}"
ate_client_stage_bundle "${WORK_DIR}" "${SMOKE_EXE}" "${ATE_DLL}"
ate_client_build_image "${WORKSPACE_ROOT}" "${WORK_DIR}"

# Hand the ATE machine the same credentials the native client uses.
CERTS_DIR="${WORK_DIR}/certs"
mkdir -p "${CERTS_DIR}"
cp -f "${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
      "${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
      "${DEPLOYMENT_DIR}/certs/out/ca-cert.pem" \
      "${CERTS_DIR}/"

# Prefer an isolated network namespace, which exercises a real network path to
# the appliance. Older podman releases do not provide the host alias, so fall
# back to sharing the host's namespace (the PA certificate also carries
# `IP.1 = ${OTPROV_IP_PA}`, so loopback still verifies).
NETWORK="bridge"
PA_HOST="${ATE_CLIENT_PA_HOST}"
if ! podman run --rm --network=bridge --entrypoint=/bin/bash \
     "${ATE_CLIENT_IMAGE}" \
     -c "timeout 5 bash -c '</dev/tcp/${ATE_CLIENT_PA_HOST}/${OTPROV_PORT_PA}'" \
     >/dev/null 2>&1; then
  echo "WARNING: ${ATE_CLIENT_PA_HOST}:${OTPROV_PORT_PA} is unreachable from a"
  echo "         bridged container; falling back to host networking."
  NETWORK="host"
  PA_HOST="${OTPROV_IP_PA}"
fi

PQ_FLAGS=()
if [[ "${ENABLE_MLKEM_TLS}" == "true" ]]; then
  PQ_FLAGS+=("--mlkem")
fi
if [[ "${ENABLE_MLDSA_TLS}" == "true" ]]; then
  PQ_FLAGS+=("--mldsa")
fi

echo "Running Windows ATE DLL test in the ATE machine container ..."
echo "  target:  ${PA_HOST}:${OTPROV_PORT_PA}"
echo "  network: ${NETWORK}"
echo "  mlkem:   ${ENABLE_MLKEM_TLS}  mldsa: ${ENABLE_MLDSA_TLS}"

status=0
ate_client_run "${NETWORK}" "${CERTS_DIR}" \
  --mtls \
  "${PQ_FLAGS[@]}" \
  --cert=certs/ate-client-cert.pem \
  --key=certs/ate-client-key.pem \
  --ca=certs/ca-cert.pem \
  --target="${PA_HOST}:${OTPROV_PORT_PA}" \
  --sku="sival" \
  --sku_auth="test_password" || status=$?

ate_client_report_status "windows-ate-dll-mtls" "${status}"

echo "Done."
