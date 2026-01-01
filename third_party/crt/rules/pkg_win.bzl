# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//third_party/crt/rules:transition.bzl", "platform_rule")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain")

def _get_toolchain_dir(cc_toolchain):
    workspace = [f for f in cc_toolchain.all_files.to_list() if f.basename == "WORKSPACE"]
    if not workspace:
        fail("Could not find the WORKSPACE of the cc_toolchain")
    return workspace[0]

def _pkg_win_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.name + ".zip")
    if ctx.attr.platform == "//platforms/x86_64:win64":
        target = "win64"
    elif ctx.attr.platform == "//third_party/crt/platforms/x86_32:win32":
        target = "win32"
    else:
        fail("Unknown platform:", ctx.attr.platform)

    toolchain = find_cc_toolchain(ctx)
    cc_toolchain = getattr(toolchain, "cc", toolchain)
    mxe = _get_toolchain_dir(cc_toolchain)

    args = [
        "--target={}".format(target),
        "--mxe={}".format(mxe.dirname),
        "--out={}".format(out.path),
    ]
    if ctx.attr.skip_dlls:
        args.append("--skip_dlls={}".format(",".join([dll for dll in ctx.attr.skip_dlls])))
    if ctx.attr.zips:
        args.append("--combine_zips={}".format(",".join([z.path for z in ctx.files.zips])))
    args.extend([src.path for src in ctx.files.srcs])

    ctx.actions.run(
        executable = ctx.executable._tool,
        arguments = args,
        inputs = ctx.files.srcs + ctx.files.zips + cc_toolchain.all_files.to_list(),
        outputs = [out],
        progress_message = "Packaging files into {}".format(out.basename),
        mnemonic = "PkgWin",
    )
    return DefaultInfo(
        files = depset([out]),
        runfiles = ctx.runfiles(files = [out]),
    )

pkg_win = platform_rule(
    implementation = _pkg_win_impl,
    attrs = {
        "srcs": attr.label_list(
            doc = "List of targets to include in this package",
            allow_files = True,
        ),
        "skip_dlls": attr.string_list(
            doc = "Names of DLLs that can be ignored in dependency analysis",
        ),
        "platform": attr.string(
            default = "//platforms/x86_64:win64",
            doc = "The target platform",
        ),
        "zips": attr.label_list(
            doc = "List of additional ZIP archives to re-pack into this archive",
            allow_files = True,
        ),
        "_tool": attr.label(
            default = "//third_party/crt/util:pkg_win",
            cfg = "host",
            executable = True,
        ),
        "_cc_toolchain": attr.label(
            default = Label("@bazel_tools//tools/cpp:current_cc_toolchain"),
        ),
    },
    fragments = ["cpp"],
    toolchains = ["@rules_cc//cc:toolchain_type"],
    incompatible_use_toolchain_transition = True,
)
