#!/bin/bash --norc
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

PROG=${0##*/}
DRIVER_DIR=${0%/*}
MXE="gcc_mxe_mingw32_files"

# Bzlmod compatibility: Find the actual directory name in external/
if [ ! -d "external/${MXE}" ]; then
    # Look for directory ending with ~gcc_mxe_mingw32_files (Bzlmod canonical name style)
    FOUND=$(find external -maxdepth 1 -name "*~${MXE}" -type d | head -n 1)
    if [ -n "$FOUND" ]; then
        MXE=${FOUND#external/}
    fi
fi

VERSION="11.3.0"
PREFIX="i686-w64-mingw32.shared"
export COMPILER_PATH="external/${MXE}/libexec/gcc/${PREFIX}/${VERSION}:external/${MXE}/bin:${DRIVER_DIR}"
export LIBRARY_PATH="external/${MXE}/${PREFIX}/lib:external/${MXE}/lib/gcc/${PREFIX}/${VERSION}"

ARGS=()
POSTARGS=()
case "${PROG}" in
    gcc)
        ARGS+=("-B" "external/${MXE}/bin/${PREFIX}-")
        ;;
esac

exec "external/${MXE}/bin/${PREFIX}-${PROG}" \
    "${ARGS[@]}" \
    "$@"\
    "${POSTARGS[@]}"
