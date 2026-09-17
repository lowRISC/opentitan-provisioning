#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Rebuilds the Wine base image used to simulate a Windows ATE machine.
#
# The tests build this image automatically when it is missing, so this script
# is only needed to refresh it after editing the Dockerfile, or to publish it.
#
# TODO: publish to us-docker.pkg.dev and pull it by digest from
# `third_party/docker/extensions.bzl`, as is done for the SoftHSM2 image, so
# that CI does not rebuild it from Debian packages.

set -e

REPO_TOP="$(cd "$(dirname "$0")/../../.." && pwd)"
source "${REPO_TOP}/util/ate_client_container.sh"

ate_client_require_podman

echo "Rebuilding ${ATE_CLIENT_BASE_IMAGE} ..."
ate_client_build_base_image "${REPO_TOP}"
