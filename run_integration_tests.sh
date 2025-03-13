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
  --prod)
    export OT_PROV_PROD_EN="yes"
    shift
    ;;
  *)
    echo "Unknown option $i"
    exit 1
    ;;
  esac
done

if [[ -n "${OT_PROV_PROD_EN}" ]]; then
  # Spawn the SPM server as a process and store its process ID.
  echo "Launching SPM server outside of container"
  . config/prod/env/spm.env
  bazelisk run //src/spm:spm_server -- \
    --port=5000 \
    "--hsm_so=${HSMTOOL_MODULE}" \
    --spm_config_dir=/var/lib/opentitan/config/prod/spm &
  SPM_COMMAND_PID=$!
fi


# Register trap to shutdown containers before exit.
# Teardown containers. This currently does not remove the container volumes.
shutdown_callback() {
  if [ -z "${DEBUG}" ]; then
    podman pod stop provapp
    podman pod rm provapp
  fi

  # Send kill signal to SPM server process and wait for it to terminate.
  if [[ -n "${OT_PROV_PROD_EN}" ]]; then
    kill "${SPM_COMMAND_PID}" 2>/dev/null
    wait "${SPM_COMMAND_PID}" 2>/dev/null
  fi
}
trap shutdown_callback EXIT


# Build and deploy containers. The ${OT_PROV_PROD_EN} envar is checked
# by `deploy_test_k8_pod.sh`.
./util/containers/deploy_test_k8_pod.sh

# Run the loadtest.
echo "Running PA loadtest ..."
bazelisk run //src/pa:loadtest -- \
    --pa_address="localhost:5001" \
    --sku_auth="test_password" \
    --parallel_clients=10 \
    --total_calls_per_method=10
echo "Done."
