#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

################################################################################
# Check usage.
################################################################################
usage() {
    echo >&2 "ERROR: $1"
    echo >&2 ""
    echo >&2 "Usage: $0 <dev|prod> <release-dir>"
    exit 1
}

################################################################################
# Parse args.
################################################################################
if [ $# != 2 ]; then
    usage "Unexpected number of arguments"
fi

CONFIG_SUBDIR=$1
if [ "${CONFIG_SUBDIR}" != "dev" ] && [ "${CONFIG_SUBDIR}" != "prod" ]; then
    usage "CONFIG_SUBDIR: ${CONFIG_SUBDIR} must be 'dev' or 'prod'"
fi

RELEASE_DIR=$2
if [ ! -d "${RELEASE_DIR}" ]; then
    usage "RELEASE_DIR: ${RELEASE_DIR} does not exist"
fi
CONFIG_DIR="$(dirname "$0")/${CONFIG_SUBDIR}"

################################################################################
# Source envars.
################################################################################
source "${CONFIG_DIR}/env/spm.env"

################################################################################
# Create deployment dir structure.
################################################################################
echo "Staging deployment directory structure ..."
if [ ! -d "${OPENTITAN_VAR_DIR}" ]; then
    echo "Creating config directory: ${OPENTITAN_VAR_DIR}."
    mkdir -p "${OPENTITAN_VAR_DIR}"
    chown "${USER}" "${OPENTITAN_VAR_DIR}"
fi

DEPLOYMENT_DIR="${OPENTITAN_VAR_DIR}/config/${CONFIG_SUBDIR}"

mkdir -p "${DEPLOYMENT_DIR}/spm"
cp -r "${CONFIG_DIR}/certs" "${DEPLOYMENT_DIR}"
cp -r "${CONFIG_DIR}/containers" "${DEPLOYMENT_DIR}"
cp -r "${CONFIG_DIR}/env" "${DEPLOYMENT_DIR}"
cp -Rf ${CONFIG_DIR}/spm/* "${DEPLOYMENT_DIR}/spm"
echo "Done."

################################################################################
# Install SoftHSM2 to deployment dir and initialize it.
################################################################################
if [ "${CONFIG_SUBDIR}" == "dev" ]; then
    echo "Installing and configuring SoftHSM2 ..."
    if [ ! -d "${DEPLOYMENT_DIR}/softhsm2" ]; then
        mkdir -p "${DEPLOYMENT_DIR}/softhsm2"
        tar -xvf "${RELEASE_DIR}/softhsm_dev.tar.xz" \
            --directory "${DEPLOYMENT_DIR}/softhsm2"
    fi

    # We create two separate SoftHSM configuration directories, one for the SPM HSM
    # and one for the offline HSM. SoftHSM2 does not provide a mechanism for assiging
    # deterministic slot IDs, so we use separate configuration directories to avoid
    # slot ID conflicts. Both SPM and Offline tokens are available on slot 0 in their
    # respective configurations.

    # SPM HSM Instance.
    ${CONFIG_DIR}/softhsm/init.sh \
        "${CONFIG_DIR}" \
        "${DEPLOYMENT_DIR}/softhsm2/softhsm2" \
        "${OPENTITAN_VAR_DIR}" \
        "${SPM_HSM_TOKEN_SPM}"

    # Offline HSM Instance.
    SOFTHSM2_CONF="${SOFTHSM2_CONF_OFFLINE}" ${CONFIG_DIR}/softhsm/init.sh \
        "${CONFIG_DIR}" \
        "${DEPLOYMENT_DIR}/softhsm2/softhsm2" \
        "${OPENTITAN_VAR_DIR}" \
        "${SPM_HSM_TOKEN_OFFLINE}"

    # Add write permissions to directories so they can be removed by the self
    # hosted GitHub runner between test runs.
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/bin
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/lib
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/lib/softhsm
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/share
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/share/man
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/share/man/man1
    chmod +w ${DEPLOYMENT_DIR}/softhsm2/softhsm2/share/man/man5

    echo "Done."
fi

################################################################################
# Install hsmtool to deployment dir.
################################################################################
echo "Installing HSM configuration utilities ..."
if [ ! -d "${OPENTITAN_VAR_DIR}/bin" ]; then
    mkdir -p "${OPENTITAN_VAR_DIR}/bin"
fi
tar -xvf "${RELEASE_DIR}/hsmutils.tar.xz" --directory "${OPENTITAN_VAR_DIR}/bin"

################################################################################
# Unpack the infrastructure release binaries (PA, SPM, ProxyBuffer, etc.).
################################################################################
echo "Unpacking release binaries and container images ..."
mkdir -p "${OPENTITAN_VAR_DIR}/release"
if [ -z "${CONTAINERS_ONLY}" ]; then
    tar -xvf "${RELEASE_DIR}/fakeregistry_binaries.tar.xz" \
        --directory "${OPENTITAN_VAR_DIR}/release"
    tar -xvf "${RELEASE_DIR}/provisioning_appliance_binaries.tar.xz" \
        --directory "${OPENTITAN_VAR_DIR}/release"
    tar -xvf "${RELEASE_DIR}/proxybuffer_binaries.tar.xz" \
        --directory "${OPENTITAN_VAR_DIR}/release"
else
    cp -f "${RELEASE_DIR}/fakeregistry_containers.tar" \
        "${OPENTITAN_VAR_DIR}/release/"
    cp -f "${RELEASE_DIR}/provisioning_appliance_containers.tar" \
        "${OPENTITAN_VAR_DIR}/release/"
    cp -f "${RELEASE_DIR}/proxybuffer_containers.tar" \
        "${OPENTITAN_VAR_DIR}/release/"
    echo "Skipping unpacking raw binaries; deploying containers only ..."
fi
echo "Done."

################################################################################
# Load and configure infrastructure containers.
################################################################################
echo "Loading containers to podman local registry ..."
# Configure podman to use the local k8s pause container.
mkdir -p ~/.config/containers
cat << EOF > ~/.config/containers/containers.conf
# Configuration autogenerated by deployment script $0
[engine]

infra_image = "podman_pause:latest"

EOF
podman load \
    -i "${OPENTITAN_VAR_DIR}/release/fakeregistry_containers.tar"
podman load \
    -i "${OPENTITAN_VAR_DIR}/release/provisioning_appliance_containers.tar"
podman load \
    -i "${OPENTITAN_VAR_DIR}/release/proxybuffer_containers.tar"
echo "Done."

################################################################################
# Generate Kube configuration files from templates.
################################################################################
find "${DEPLOYMENT_DIR}/containers/" -name "*.tmpl" -print0 | \
while IFS= read -r -d '' template; do
    file="${template%.tmpl}"
    envsubst < "${template}" > "${file}"
done

################################################################################
# Generate gRPC certificates.
################################################################################
echo "Generating gRPC certificates ..."
${CONFIG_DIR}/certs/gen_certs.sh
echo "Done."

################################################################################
# Launch containers with podman.
################################################################################
echo "Launching containers ..."
podman play kube "${DEPLOYMENT_DIR}/containers/provapp.yml" \
    --configmap "${DEPLOYMENT_DIR}/env/spm.yml"
echo "Done."
