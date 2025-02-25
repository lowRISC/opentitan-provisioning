# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

_VENDOR_REPO_TEMPLATE = """
def vendor_repo(name):
    native.local_repository(
        name = name,
        path = "{vendor_repo_dir}",
    )
"""

_BUILD = """
exports_files(glob(["**"]))
"""

def _vendor_repo_setup_impl(rctx):
    vendor_repo_dir = rctx.os.environ.get("VENDOR_REPO_DIR", rctx.attr.dummy)
    rctx.file("repos.bzl", _VENDOR_REPO_TEMPLATE.format(vendor_repo_dir = vendor_repo_dir))
    rctx.file("BUILD.bazel", _BUILD)

vendor_repo_setup = repository_rule(
    implementation = _vendor_repo_setup_impl,
    attrs = {
        "dummy": attr.string(
            mandatory = True,
            doc = "Location of the dummy vendor repo directory.",
        ),
    },
    environ = ["VENDOR_REPO_DIR"],
)
