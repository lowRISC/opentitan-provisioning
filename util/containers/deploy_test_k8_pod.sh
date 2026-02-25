#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# Deploy the provisioning appliance services.
export CONTAINERS_ONLY="yes"

if [[ -z "${ENABLE_MLKEM}" ]]; then
    export ENABLE_MLKEM="false"
fi

DEPLOY_ENV="dev"
if [[ -n "${OT_PROV_PROD_EN}" ]]; then
    DEPLOY_ENV="prod"
fi

if [[ ! -n "${RELEASE_DIR}" ]]; then
   echo "No release tarball provided. Building release bundle ..."
   REPO_TOP=$(git rev-parse --show-toplevel)
   bazelisk build //release:release_bundle --define "env=${DEPLOY_ENV}"
   bazelisk build //release:fakeregistry_containers_tar
   bazelisk build //release:provisioning_appliance_containers_tar
   bazelisk build //release:proxybuffer_containers_tar
   bazelisk build //release:softhsm_dev
   RELEASE_DIR=${REPO_TOP}/bazel-bin/release
fi

# Remove the deployment directory if it exists.
if [ -d "${OPENTITAN_VAR_DIR}" ]; then
    rm -rf ${OPENTITAN_VAR_DIR}
fi

mkdir -p ${OPENTITAN_VAR_DIR}/release
mv ${RELEASE_DIR}/release_bundle.tar.xz ${OPENTITAN_VAR_DIR}
mv ${RELEASE_DIR}/fakeregistry_containers.tar ${OPENTITAN_VAR_DIR}/release
mv ${RELEASE_DIR}/provisioning_appliance_containers.tar ${OPENTITAN_VAR_DIR}/release
mv ${RELEASE_DIR}/proxybuffer_containers.tar ${OPENTITAN_VAR_DIR}/release
mv ${RELEASE_DIR}/softhsm_dev.tar.xz ${OPENTITAN_VAR_DIR}/release

tar xvf ${OPENTITAN_VAR_DIR}/release_bundle.tar.xz -C ${OPENTITAN_VAR_DIR}
tar xvf ${OPENTITAN_VAR_DIR}/config/config.tar.gz -C ${OPENTITAN_VAR_DIR}

${OPENTITAN_VAR_DIR}/config/deploy.sh ${DEPLOY_ENV}

. ${REPO_TOP}/config/env/${DEPLOY_ENV}/spm.env

TOKEN_INIT_SCRIPT="${OPENTITAN_VAR_DIR}/config/token_init.sh"
if [ -f "${TOKEN_INIT_SCRIPT}" ]; then
    export DEPLOY_ENV="${DEPLOY_ENV}"
    if [[ "${DEPLOY_ENV}" == "dev" ]]; then
        echo "Initializing tokens for dev environment ..."
        echo " -- Step 1: Initialize SPM HSM with a new identity key and wrapping key."
        ${TOKEN_INIT_SCRIPT} --action "spm-init"
        echo " -- Step 2: Initialize offline HSM with secrets and CA private key."
        ${TOKEN_INIT_SCRIPT} --action "offline-common-init"
        echo " -- Step 3: Export the offline HSM secrets."
        ${TOKEN_INIT_SCRIPT} --action "offline-common-export"
        echo " -- Step 4: Initialize the SPM with all SKU private keys."
        ${TOKEN_INIT_SCRIPT} --action "spm-sku-init" --sku sival --sku test_mldsa --sku cr01 --sku pi01 --sku ti01
    fi
    echo " -- Step 5: Generate the CSRs for all SKUs."
    ${TOKEN_INIT_SCRIPT} --action "spm-sku-csr" --sku sival --sku test_mldsa --sku cr01 --sku pi01 --sku ti01
    echo " -- Step 6: Generate the root certificate."
    ${TOKEN_INIT_SCRIPT} --action "offline-ca-root-certgen"
    echo " -- Step 7: Endorse the CSRs for all SKUs."
    ${TOKEN_INIT_SCRIPT} --action "offline-sku-certgen" --sku sival --sku test_mldsa --sku cr01 --sku pi01 --sku ti01

    echo "Print object attributes ..."
    ${TOKEN_INIT_SCRIPT} --action "spm-init" --show
    ${TOKEN_INIT_SCRIPT} --action "offline-common-init" --show
    ${TOKEN_INIT_SCRIPT} --action "spm-sku-init" --sku sival --sku test_mldsa --sku cr01 --sku pi01 --sku ti01 --show
fi

echo "Provisioning services launched."
echo "Run the following to teardown:"
echo "  podman pod stop provapp && podman pod rm provapp"
