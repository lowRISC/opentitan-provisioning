#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

readonly REPO_TOP="$(dirname "$0")"
readonly OPENTITAN_VAR_DIR="/var/lib/opentitan"

sudo apt update
sed -e '/^$/d' -e '/^#/d' -e 's/#.*//' \
  < "$REPO_TOP/apt-requirements.txt" \
  | sudo xargs apt install -y
sudo apt clean

go install github.com/bazelbuild/bazelisk@v1.27.0

# Create Project config settings directory.
if [ ! -d "${OPENTITAN_VAR_DIR}" ]; then
  echo "Creating config directory: ${OPENTITAN_VAR_DIR}. This requires sudo."
  sudo mkdir -p "${OPENTITAN_VAR_DIR}"
  sudo chown "${USER}" "${OPENTITAN_VAR_DIR}"
fi
