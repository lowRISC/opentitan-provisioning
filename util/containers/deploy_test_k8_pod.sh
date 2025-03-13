#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

readonly REPO_TOP=$(git rev-parse --show-toplevel)

# Build release containers.
bazelisk build --stamp //release:hsmutils
bazelisk build --stamp //release:provisioning_appliance_containers_tar
bazelisk build --stamp //release:proxybuffer_containers_tar
bazelisk build --stamp //release:softhsm_dev

# Deploy the provisioning appliance services.
export CONTAINERS_ONLY="yes"

CONFIG_SUBDIR="dev"
if [[ -n "${OT_PROV_PROD_EN}" ]]; then
    CONFIG_SUBDIR="prod"
fi

. ${REPO_TOP}/config/${CONFIG_SUBDIR}/env/spm.env
${REPO_TOP}/config/deploy.sh ${CONFIG_SUBDIR} ${REPO_TOP}/bazel-bin/release

TOKEN_INIT_SCRIPT="${REPO_TOP}/config/${CONFIG_SUBDIR}/token_init.sh"
if [ -f "${TOKEN_INIT_SCRIPT}" ]; then
    echo "Initializing tokens ..."
    ${TOKEN_INIT_SCRIPT}
fi

echo "Provisioning services launched."
echo "Run the following to teardown:"
echo "  podman pod stop provapp && podman pod rm provapp"
