# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

def _windows_platform_transition_impl(settings, attr):
    return {
        "//command_line_option:platforms": "@crt//platforms/x86_32:win32",
    }

windows_platform_transition = transition(
    implementation = _windows_platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _windows_binary_impl(ctx):
    # The dependency 'dep' is now built in the windows configuration.
    # ctx.attr.dep is a list because the transition is 1:1.
    dep = ctx.attr.dep[0]

    # Determine the output file name based on the target name.
    # We expect a DLL for Windows binaries (linkshared=True).
    output = ctx.actions.declare_file(ctx.label.name + ".dll")

    found = False
    for f in dep[DefaultInfo].files.to_list():
        if f.extension == "dll":
            ctx.actions.symlink(output = output, target_file = f)
            found = True
            break

    if not found:
        # Fallback: just forward everything if no DLL found (though unexpected for this specific use case)
        # Or fail. Let's fail to be explicit, as we expect a DLL.
        # But maybe it's an exe?
        for f in dep[DefaultInfo].files.to_list():
            if f.extension == "exe":
                ctx.actions.declare_file(ctx.label.name + ".exe")
                ctx.actions.symlink(output = output, target_file = f)
                found = True
                break

    if not found:
        fail("Could not find .dll or .exe in dependency output. Files: " + str(dep[DefaultInfo].files.to_list()))

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
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
