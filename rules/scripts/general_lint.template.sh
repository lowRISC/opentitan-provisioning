#!/usr/bin/env bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Set mode and lint tool.
LINT_TOOL=@@LINT_TOOL@@
MODE=@@MODE@@
WORKSPACE="@@WORKSPACE@@"
RUNNER_SH=@@RUNNER_SH@@

lint_tool=$(readlink "$LINT_TOOL")
runner_sh=$(readlink "$RUNNER_SH")

# Change directories based on whether the mode is to "fix" or to "diff".
if [[ -n "${WORKSPACE}" ]]; then
    REPO="$(dirname "$(realpath ${WORKSPACE})")"
    cd "${REPO}" || exit 1
elif [[ -n "${BUILD_WORKSPACE_DIRECTORY+is_set}" ]]; then
    cd "${BUILD_WORKSPACE_DIRECTORY}" || exit 1
else
    echo "Neither WORKSPACE nor BUILD_WORKSPACE_DIRECTORY were set."
    echo "If this is a test rule, add 'workspace = \"//:WORKSPACE\"' to your rule."
    exit 1
fi

# Find all files with designated patterns to check.
if [[ $# != 0 ]]; then
    FILES="$@"
else
    FILES=$(find . \
        -type f \
        @@EXCLUDE_PATTERNS@@ \
        \( @@INCLUDE_PATTERNS@@ \) \
        -print)
fi

if [[ -z "$FILES" ]]; then
  echo "Error no files found to lint for pattern: \"$INCLUDE_PATTERNS\"."
  exit 1
fi

# Execute the runner script.
source "$runner_sh"
