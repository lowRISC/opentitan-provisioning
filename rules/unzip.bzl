# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def _unzip_archive_impl(ctx):
    out_dir = ctx.actions.declare_directory(ctx.attr.out)
    ctx.actions.run_shell(
        inputs = [ctx.file.src],
        outputs = [out_dir],
        command = "unzip -q -o %s -d %s" % (ctx.file.src.path, out_dir.path),
        mnemonic = "UnzipArchive",
    )
    return [DefaultInfo(files = depset([out_dir]))]

unzip_archive = rule(
    implementation = _unzip_archive_impl,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(mandatory = True),
    },
)
