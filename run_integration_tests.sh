#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Parse command line options.
for i in "$@"; do
  case $i in
  # -d option: Activate debug mode, which will not tear down containers if
  # there is a failure so the failure can be inspected.
  -d | --debug)
    export DEBUG="yes"
    shift
    ;;
  *)
    echo "Unknown option $i"
    exit 1
    ;;
  esac
done

# Register trap to shutdown containers before exit.
# Teardown containers. This currently does not remove the container volumes.
shutdown_containers() {
  podman pod stop provapp
  podman pod rm provapp
}
if [ -z "${DEBUG}" ]; then
  trap shutdown_containers EXIT
fi

# Build and deploy containers.
./util/containers/deploy_test_k8_pod.sh

# Run the loadtest on each SKU.
SKUS=("tpm_1" "sival")
for sku in "${SKUS[@]}"; do
  echo "Running PA loadtest with sku: ${sku} ..."
  bazelisk run //src/pa:loadtest -- \
    --pa_address="localhost:5001" \
    --sku="${sku}" \
    --sku_auth="test_password" \
    --parallel_clients=10 \
    --total_calls_per_client=10
done

# Run the reference CP flow.
CP_SKUS=("sival")
for sku in "${CP_SKUS[@]}"; do
  echo "Running reference CP flow with sku: ${sku} ..."
  bazelisk run //src/ate/test_programs:cp -- \
    --pa_socket="localhost:5001" \
    --sku="${sku}" \
    --sku_auth_pw="test_password"
done
