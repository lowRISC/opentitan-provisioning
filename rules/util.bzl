# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def _deb_package_impl(rctx):
    rctx.download_and_extract(rctx.attr.url, sha256 = rctx.attr.sha256)
    rctx.extract("data.tar.xz")
    rctx.symlink("usr/bin/clang-format-14", "clang-format")
    rctx.symlink(rctx.attr.build_file, "BUILD")

deb_package = repository_rule(
    implementation = _deb_package_impl,
    attrs = {
        "url": attr.string(mandatory = True),
        "sha256": attr.string(mandatory = True),
        "build_file": attr.label(mandatory = True),
    },
)
