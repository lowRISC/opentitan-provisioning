#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -ex

: "${REPO_TOP:=$(git rev-parse --show-toplevel)}"

# Prefetch bazel airgapped dependencies.
. ${REPO_TOP}/util/airgapped_builds/prep-bazel-airgapped-build.sh -f

# Remove the airgapped network namespace.
remove_airgapped_netns() {
  sudo ip netns delete airgapped
}
trap remove_airgapped_netns EXIT

# Set up a network namespace named "airgapped" with access to loopback.
sudo ip netns add airgapped
sudo ip netns exec airgapped ip addr add 127.0.0.1/8 dev lo
sudo ip netns exec airgapped ip link set dev lo up

# Enter the network namespace and perform several builds.
sudo ip netns exec airgapped sudo -u "$USER" \
  env \
    BAZEL_PYTHON_WHEELS_REPO="${PWD}/bazel-airgapped/ot_python_wheels" \
  "${PWD}/bazel-airgapped/bazel" build                               \
    --distdir="${PWD}/bazel-airgapped/bazel-distdir"                 \
    --repository_cache="${PWD}/bazel-airgapped/bazel-cache"          \
    //...
exit 0
