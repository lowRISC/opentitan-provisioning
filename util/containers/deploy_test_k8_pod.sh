#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

readonly REPO_TOP=$(git rev-parse --show-toplevel)

# Build release containers.
bazelisk build --stamp //release:provisioning_appliance_containers_tar
bazelisk build --stamp //release:proxybuffer_containers_tar
bazelisk build --stamp //release:softhsm_dev
bazelisk build --stamp //release:hsmutils

# Deploy the provisioning appliance services.
export CONTAINERS_ONLY="yes"
. ${REPO_TOP}/config/dev/env/spm.env
${REPO_TOP}/config/dev/deploy.sh ${REPO_TOP}/bazel-bin/release

echo "Initializing tokens ..."
${REPO_TOP}/config/dev/token_init.sh

echo "Provisioning services launched."
echo "Run the following to teardown:"
echo "  podman pod stop provapp && podman pod rm provapp"
