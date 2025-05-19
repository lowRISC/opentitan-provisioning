#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

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

CONFIG_SUBDIR="dev"
if [[ -n "${OT_PROV_PROD_EN}" ]]; then
  CONFIG_SUBDIR="prod"
fi

export OPENTITAN_VAR_DIR=${OPENTITAN_VAR_DIR:-$(pwd)/.ot${CONFIG_SUBDIR}}

DEPLOYMENT_DIR="${OPENTITAN_VAR_DIR}/config/${CONFIG_SUBDIR}"

# SPM_PID_FILE is used to store the process ID of the SPM server process.
# This is used to send a kill signal to the process when the script exits.
# The variable is only set if the --prod flag is passed.
SPM_PID_FILE="/tmp/spm.pid"

# spm_server_try_stop sends a kill signal to the SPM server process if it is
# running. It also waits for the process to terminate and removes the PID file.
# This function is idempotent and can be called multiple times.
spm_server_try_stop() {
  if [ -f "${SPM_PID_FILE}" ]; then
    SPM_PID=$(cat "${SPM_PID_FILE}")
    kill "${SPM_PID}" 2>/dev/null || true
    wait "${SPM_PID}" 2>/dev/null || true
    rm "${SPM_PID_FILE}"
  fi
}

# Unconditionally stop and remove the pod if it exists.
# The --ignore flag is used to suppress errors if the pod does not exist.
podman pod stop provapp --ignore
podman pod rm provapp --ignore

# Register trap to shutdown containers before exit.
# Teardown containers. This currently does not remove the container volumes.
shutdown_callback() {
  if [ -z "${DEBUG}" ]; then
    podman pod stop provapp
    podman pod rm provapp
  fi

  # Send kill signal to SPM server process and wait for it to terminate.
  if [[ -n "${OT_PROV_PROD_EN}" ]]; then
    spm_server_try_stop
  fi
}
trap shutdown_callback EXIT

# Build and deploy containers. The ${OT_PROV_PROD_EN} envar is checked
# by `deploy_test_k8_pod.sh`.
./util/containers/deploy_test_k8_pod.sh

. ${DEPLOYMENT_DIR}/env/spm.env

# Unpack firmware and OpenOCD binaries.
bazelisk build //third_party/lowrisc/ot_fw:orchestrator_unzip
DEPLOYMENT_BIN_DIR="${OPENTITAN_VAR_DIR}/bin"
BUILD_BIN_DIR="bazel-bin/third_party/lowrisc/ot_fw/orchestrator/runfiles/lowrisc_opentitan"
cp "${BUILD_BIN_DIR}"/sw/device/silicon_creator/manuf/base/sram_cp_provision*.elf "${DEPLOYMENT_BIN_DIR}"
cp "${BUILD_BIN_DIR}"/sw/device/silicon_creator/manuf/base/sram_ft_individualize*.elf "${DEPLOYMENT_BIN_DIR}"
cp "${BUILD_BIN_DIR}"/sw/device/silicon_creator/manuf/base/ft_personalize*.bin "${DEPLOYMENT_BIN_DIR}"
cp "${BUILD_BIN_DIR}"/third_party/openocd/build_openocd/bin/openocd "${DEPLOYMENT_BIN_DIR}"
chmod +x "${DEPLOYMENT_BIN_DIR}"/openocd

if [[ -n "${OT_PROV_PROD_EN}" ]]; then
  # Spawn the SPM server as a process and store its process ID.
  echo "Launching SPM server outside of container"
  . config/prod/env/spm.env
  spm_server_try_stop
  bazelisk run //src/spm:spm_server -- \
    --enable_tls=true \
    --service_cert="${DEPLOYMENT_DIR}/certs/out/spm-service-cert.pem" \
    --service_key="${DEPLOYMENT_DIR}/certs/out/spm-service-key.pem" \
    --ca_root_certs=${DEPLOYMENT_DIR}/certs/out/ca-cert.pem \
    --port=${OTPROV_PORT_SPM} \
    "--hsm_so=${HSMTOOL_MODULE}" \
    --spm_auth_config="sku_auth.yml" \
    "--spm_config_dir=${DEPLOYMENT_DIR}/spm" &
  echo $! > "${SPM_PID_FILE}"
fi
