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
        # Otherwise use the dummy label's package path.
        # We rely on the dummy label pointing to a file inside the directory.
        dummy_path = rctx.path(rctx.attr.dummy_label)
        path = dummy_path.dirname
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
        rctx.symlink(path.get_child(f), f)

vendor_repo = repository_rule(
    implementation = _vendor_repo_impl,
    attrs = {
        "dummy_label": attr.label(
            default = Label("//src/vendor:BUILD.bazel"),
            doc = "Label pointing to a file in the dummy vendor directory, used to resolve the path.",
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
