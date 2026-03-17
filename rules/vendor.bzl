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

def _vendor_repo_impl(rctx):
    # If VENDOR_REPO_DIR is set, use it.
    path = rctx.os.environ.get("VENDOR_REPO_DIR")
    if not path:
        # Otherwise use the default vendor label's package path.
        # We rely on the label pointing to a file inside the directory.
        default_vendor_path = rctx.path(rctx.attr.default_vendor_label)
        path = default_vendor_path.dirname
    else:
        path = rctx.path(path)

    # Symlink contents.
    # We use 'ls -A' to list all files including dotfiles except . and ..
    # Note: this requires 'ls' to be available (Linux/macOS).
    result = rctx.execute(["ls", "-A", path])
    if result.return_code != 0:
        fail("Failed to list vendor repo directory '{}': {}".format(path, result.stderr))

    files = result.stdout.splitlines()
    for f in files:
        if f not in ["BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel"]:
            rctx.symlink(path.get_child(f), f)

vendor_repo = repository_rule(
    implementation = _vendor_repo_impl,
    attrs = {
        "default_vendor_label": attr.label(
            default = Label("//src/vendor:BUILD.bazel"),
            doc = "Label pointing to a file in the default vendor directory, used to resolve the path if VENDOR_REPO_DIR is not set.",
        ),
    },
    environ = ["VENDOR_REPO_DIR"],
    local = True,
)

def _vendor_deps_impl(ctx):
    vendor_repo(name = "vendor_repo")

vendor_deps = module_extension(
    implementation = _vendor_deps_impl,
)
