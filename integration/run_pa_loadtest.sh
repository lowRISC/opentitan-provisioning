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

SKU_NAMES="sival,cr01,pi01,ti01"

# Run the PA loadtest.
echo "Running PA loadtest ..."
bazelisk run //src/pa:loadtest -- \
   --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
   --client_cert="${DEPLOYMENT_DIR}/certs/out/ate-client-cert.pem" \
   --client_key="${DEPLOYMENT_DIR}/certs/out/ate-client-key.pem" \
   --enable_tls=true \
   --hsm_so="${HSMTOOL_MODULE}" \
   --pa_address="${OTPROV_DNS_PA}:${OTPROV_PORT_PA}" \
   --parallel_clients=5 \
   --sku_auth="test_password" \
   --sku_names="${SKU_NAMES}" \
   --spm_config_dir="${DEPLOYMENT_DIR}/spm" \
   --total_duts=10
echo "Done."

