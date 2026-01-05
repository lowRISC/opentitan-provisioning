#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Explicitly enable job control so that we can run the SPM server
# in the background and still be able to run other commands in parallel.
set -m

export ENABLE_MLKEM="true"

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

# Run the TLS connection test.
echo "Running TLS connection test ..."
bazelisk run //src/ate/test_programs:tls_test -- \
  --enable_mtls=true \
  --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
  --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
  --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
  --pa_target="ipv4:${OTPROV_IP_PA}:${OTPROV_PORT_PA}" \
  --sku="sival" \
  --sku_auth_pw="test_password"

echo "Done."

