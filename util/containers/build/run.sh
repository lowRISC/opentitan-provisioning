#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

if ! command -v podman &> /dev/null
then
    echo "podman could not be found."
    echo "Please install via 'sudo apt install podman'"
    exit
fi

CONTAINER_USER=dev
BAZEL_CACHE="${HOME}/.cache/bazel/_bazel_${CONTAINER_USER}"
REPO_TOP="$(pwd)"

# We want Bazel to place the cache in a path that is accessible to both the
# container and the host, and thus we use the ${HOME} host variable to
# achieve that.
# Podman maps the root user GUID=0 to the user GUID on the host side.
BAZEL_CACHE_CONTAINER="${HOME}/.cache/bazel/_bazel_${CONTAINER_USER}"

mkdir -p "${BAZEL_CACHE}"

# Set the Bazel output_user_root to the container volume mapping to avoid
# Bazel default to /root/.cache inside the container.
COMMAND="echo startup --output_user_root=${BAZEL_CACHE_CONTAINER} > /root/.bazelrc && bash"

# TODO: Consider switching to a network namespace for better isolation.
podman run -t -i \
  -v "${REPO_TOP}:/working_dir/src" \
  -v "${BAZEL_CACHE}:${BAZEL_CACHE_CONTAINER}" \
  --network=host \
  --hostname provisioning-builder \
  --workdir=/working_dir/src \
  ot-prov-dev:latest \
  "${COMMAND}"
