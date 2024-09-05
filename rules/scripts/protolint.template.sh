#!/usr/bin/env bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

PROTOLINT=@@PROTOLINT@@
MODE=@@MODE@@
WORKSPACE="@@WORKSPACE@@"

protolint=$(readlink "$PROTOLINT")

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

# Perfom the "diff" or "fix" operation.
case "$MODE" in
    diff)
        echo "$FILES" | xargs "${protolint}"
        exit $?
        ;;
    fix)
        echo "$FILES" | xargs "${protolint}" -fix
        ;;
    *)
        echo "Unknown mode: $MODE"
        exit 2
esac
