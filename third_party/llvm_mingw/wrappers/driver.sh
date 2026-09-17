#!/bin/bash --norc
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

PROG=${0##*/}
DRIVER_DIR=${0%/*}
LLVM_MINGW="llvm_mingw_files"

# Find the actual directory name in external/ for Bzlmod compatibility.
if [ ! -d "external/${LLVM_MINGW}" ]; then
    FOUND=$(find external -maxdepth 1 \( -name "*~${LLVM_MINGW}" -o -name "*+${LLVM_MINGW}" \) -type d | head -n 1)
    if [ -n "$FOUND" ]; then
        LLVM_MINGW=${FOUND#external/}
    fi
fi

PREFIX="i686-w64-mingw32"
ARGS=()

if [ "${PROG}" = "gcc" ] || [ "${PROG}" = "g++" ]; then
    IS_COMPILE=0
    for arg in "$@"; do
        case "$arg" in
            -c|-E|-S)
                IS_COMPILE=1
                break
                ;;
        esac
    done

    CLANG_INCLUDE_DIR=$(find "external/${LLVM_MINGW}/lib/clang" -maxdepth 2 -name "include" -type d | head -n 1)

    ARGS+=(
        "-no-canonical-prefixes"
        "-Wno-unused-command-line-argument"
    )
    if [ "${IS_COMPILE}" -eq 1 ]; then
        ARGS+=(
            "-nostdinc"
            "-isystem" "external/${LLVM_MINGW}/${PREFIX}/include/c++/v1"
            "-isystem" "${CLANG_INCLUDE_DIR}"
            "-isystem" "external/${LLVM_MINGW}/${PREFIX}/include"
        )
    else
        # Use g++ driver for linking so libc++ and libunwind are linked in the proper order,
        # link them statically so Windows DLLs/executables are self-contained, and include
        # the Protobuf weak-descriptor section stub for Clang PE-COFF targets.
        PROG="g++"
        ARGS+=(
            "-static"
            "-x" "c" "${DRIVER_DIR}/pb_defaults_stub.c" "-x" "none"
        )
    fi
fi

exec "external/${LLVM_MINGW}/bin/${PREFIX}-${PROG}" \
    "${ARGS[@]}" \
    "$@"
