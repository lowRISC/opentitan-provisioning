# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

ExecConfigInfo = provider(fields = ["program", "params", "data", "preparation", "substitutions"])

def _exec_config_impl(ctx):
    return [ExecConfigInfo(
        program = ctx.attr.program,
        params = [ctx.expand_location(p, ctx.attr.data) for p in ctx.attr.params],
        data = [f for f in ctx.files.data],
        preparation = ctx.attr.preparation,
        substitutions = {k: ctx.expand_location(v, ctx.attr.data) for k, v in ctx.attr.substitutions.items()},
    )]

exec_config = rule(
    implementation = _exec_config_impl,
    attrs = {
        "program": attr.label(
            doc = "Program providing execution services for a platform",
            executable = True,
            cfg = "exec",
        ),
        "data": attr.label_list(allow_files = True, doc = "Files needed at runtime."),
        "params": attr.string_list(doc = "Parameters for the program"),
        "preparation": attr.string(default = "none", values = ["none", "windows"], doc = "Special preparation type"),
        "substitutions": attr.string_dict(doc = "Substitutions to apply at runtime"),
    },
)
