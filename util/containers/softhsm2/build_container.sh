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

podman build -t us-docker.pkg.dev/opentitan/opentitan-public/ot-prov-softhsm2 \
  -f util/containers/softhsm2/Dockerfile util/containers/softhsm2
