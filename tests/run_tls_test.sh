#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Explicitly enable job control so that we can run the SPM server
# in the background and still be able to run other commands in parallel.
set -m

# Ensure we are running from the repository root
cd "$(dirname "$0")/.."

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

bazelisk build //src/ate/test_programs:tls_test
TLS_TEST_BIN="$(pwd)/bazel-bin/src/ate/test_programs/tls_test_/tls_test"

CERTS_OUT="${DEPLOYMENT_DIR}/certs/out"
BASE_ARGS=(
  --enable_mtls=true
  --pa_target="ipv4:${OTPROV_IP_PA}:${OTPROV_PORT_PA}"
  --sku="sival"
  --sku_auth_pw="test_password"
)

if [[ "${OT_PROV_MIXED_TLS}" != "yes" ]]; then
  echo "Running TLS connection test ..."
  "${TLS_TEST_BIN}" "${BASE_ARGS[@]}" \
    --expect_pqc=true \
    --client_cert="${CERTS_OUT}/ate-client-cert.pem" \
    --client_key="${CERTS_OUT}/ate-client-key.pem" \
    --ca_root_certs="${CERTS_OUT}/ca-cert.pem"
  echo "Done."
  exit 0
fi

# Mixed PQ/classical migration test suite against containerized PA/PB + SPM.
# Servers run with a mixed CA bundle and RSA fallback certs.
echo "=== [1/2] PQC client -> Mixed PA -> Mixed SPM (expect full PQC) ==="
"${TLS_TEST_BIN}" "${BASE_ARGS[@]}" \
  --expect_pqc=true \
  --client_cert="${CERTS_OUT}/ate-client-cert.pem" --client_key="${CERTS_OUT}/ate-client-key.pem" \
  --ca_root_certs="${CERTS_OUT}/ca-cert.pem"

if podman logs provapp-paserver-1 2>&1 | grep -q "TLS mixed mode"; then
  echo "Error: unexpected mixed-mode fallback warning during PQC-to-PQC run"
  dump_pa_logs
  exit 1
fi

echo "=== [2/2] Legacy TLS 1.2 RSA client -> Mixed PA (expect RSA fallback) ==="
"${TLS_TEST_BIN}" "${BASE_ARGS[@]}" \
  --legacy_tls12=true --expect_pqc=false \
  --client_cert="${CERTS_OUT}/ate-client-rsa-cert.pem" \
  --client_key="${CERTS_OUT}/ate-client-rsa-key.pem" \
  --ca_root_certs="${CERTS_OUT}/ca-rsa-cert.pem"

if ! podman logs provapp-paserver-1 2>&1 | grep -q "TLS mixed mode (server,"; then
  echo "Error: expected PA logs to contain server-side mixed-mode fallback warning"
  dump_pa_logs
  exit 1
fi
echo "Done."

