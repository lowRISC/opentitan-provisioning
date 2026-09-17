# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def _windows_platform_transition_impl(settings, attr):
    return {
        "//command_line_option:platforms": "//third_party/llvm_mingw:win32",
    }

windows_platform_transition = transition(
    implementation = _windows_platform_transition_impl,
    inputs = [],
    outputs = [
        "//command_line_option:platforms",
    ],
)

def _windows_binary_impl(ctx):
    # The dependency 'dep' is now built in the windows configuration.
    # ctx.attr.dep is a list because the transition is 1:1.
    dep = ctx.attr.dep[0]

    # Determine the output file name based on the target name. DLLs are
    # produced by cc_binary targets with linkshared = True, executables by
    # regular cc_binary targets.
    extension = ctx.attr.extension
    output = ctx.actions.declare_file(ctx.label.name + "." + extension)

    found = False
    for f in dep[DefaultInfo].files.to_list():
        if f.extension == extension:
            ctx.actions.symlink(output = output, target_file = f)
            found = True
            break

    if not found:
        fail("Could not find .{} in dependency output. Files: {}".format(
            extension,
            str(dep[DefaultInfo].files.to_list()),
        ))

    return [
        DefaultInfo(
            files = depset([output]),
            runfiles = dep[DefaultInfo].default_runfiles,
        ),
    ]

windows_binary = rule(
    implementation = _windows_binary_impl,
    attrs = {
        "dep": attr.label(cfg = windows_platform_transition),
        "extension": attr.string(
            default = "dll",
            values = ["dll", "exe"],
            doc = "Artifact extension produced by `dep`.",
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
