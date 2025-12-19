# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def _deb_package_impl(rctx):
    rctx.download_and_extract(rctx.attr.url, sha256 = rctx.attr.sha256)
    rctx.extract("data.tar.xz")

    # Download and extract extra packages (libraries)
    for url, sha256 in rctx.attr.extra_debs.items():
        rctx.download_and_extract(url, sha256 = sha256)
        rctx.extract("data.tar.xz")

    rctx.symlink("usr/bin/clang-format-14", "clang-format-bin")

    # Create the wrapper script to set LD_LIBRARY_PATH
    wrapper_content = """#!/bin/bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REAL_BINARY="$DIR/clang-format-bin"
LIB_DIR="$DIR/usr/lib/x86_64-linux-gnu"
export LD_LIBRARY_PATH="$LIB_DIR:$LD_LIBRARY_PATH"
exec "$REAL_BINARY" "$@"
"""
    rctx.file("clang-format", content = wrapper_content, executable = True)

    rctx.symlink(rctx.attr.build_file, "BUILD")

deb_package = repository_rule(
    implementation = _deb_package_impl,
    attrs = {
        "url": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "build_file": attr.label(mandatory = True),
        "extra_debs": attr.string_dict(default = {}),
    },
)
