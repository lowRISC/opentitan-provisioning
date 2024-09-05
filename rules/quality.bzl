# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Linting rules for OT Provisioning."""

load("@bazel_skylib//lib:shell.bzl", "shell")

def _ensure_tag(tags, *tag):
    for t in tag:
        if t not in tags:
            tags.append(t)
    return tags

################################################################################
# gofmt
################################################################################
def _gofmt_impl(ctx):
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    exclude_patterns = ["\\! -path {}".format(shell.quote(p)) for p in ctx.attr.exclude_patterns]
    include_patterns = ["-name {}".format(shell.quote(p)) for p in ctx.attr.patterns]
    substitutions = {
        "@@EXCLUDE_PATTERNS@@": " ".join(exclude_patterns),
        "@@INCLUDE_PATTERNS@@": " -o ".join(include_patterns),
        "@@GOFMT@@": shell.quote(ctx.executable.gofmt.short_path),
        "@@DIFF_COMMAND@@": shell.quote(ctx.attr.diff_command),
        "@@MODE@@": shell.quote(ctx.attr.mode),
    }
    ctx.actions.expand_template(
        template = ctx.file._runner,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    return DefaultInfo(
        files = depset([out_file]),
        runfiles = ctx.runfiles(files = [ctx.executable.gofmt]),
        executable = out_file,
    )

gofmt_attrs = {
    "patterns": attr.string_list(
        default = ["*.go"],
        doc = "Filename patterns for format checking",
    ),
    "exclude_patterns": attr.string_list(
        doc = "Filename patterns to exlucde from format checking",
    ),
    "mode": attr.string(
        default = "diff",
        values = ["diff", "fix"],
        doc = "Execution mode: display diffs or fix formatting",
    ),
    "diff_command": attr.string(
        default = "diff -u",
        doc = "Command to execute to display diffs",
    ),
    "gofmt": attr.label(
        default = "@go_sdk//:bin/gofmt",
        allow_single_file = True,
        cfg = "host",
        executable = True,
        doc = "The gofmt executable",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:gofmt.template.sh",
        allow_single_file = True,
    ),
}

gofmt_fix = rule(
    implementation = _gofmt_impl,
    attrs = gofmt_attrs,
    executable = True,
)

_gofmt_test = rule(
    implementation = _gofmt_impl,
    attrs = gofmt_attrs,
    test = True,
)

def gofmt_check(**kwargs):
    tags = kwargs.get("tags", [])

    # Note: the "external" tag is a workaround for bazelbuild#15516.
    kwargs["tags"] = _ensure_tag(tags, "no-sandbox", "no-cache", "external")
    _gofmt_test(**kwargs)

################################################################################
# clang-format
################################################################################
def _clang_format_impl(ctx):
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    exclude_patterns = ["\\! -path {}".format(shell.quote(p)) for p in ctx.attr.exclude_patterns]
    include_patterns = ["-name {}".format(shell.quote(p)) for p in ctx.attr.patterns]
    workspace = ctx.file.workspace.path if ctx.file.workspace else ""
    substitutions = {
        "@@EXCLUDE_PATTERNS@@": " ".join(exclude_patterns),
        "@@INCLUDE_PATTERNS@@": " -o ".join(include_patterns),
        "@@CLANG_FORMAT@@": shell.quote(ctx.attr.clang_format_command),
        "@@DIFF_COMMAND@@": shell.quote(ctx.attr.diff_command),
        "@@MODE@@": shell.quote(ctx.attr.mode),
        "@@WORKSPACE@@": workspace,
    }
    ctx.actions.expand_template(
        template = ctx.file._runner,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    return DefaultInfo(
        files = depset([out_file]),
        executable = out_file,
    )

clang_format_attrs = {
    "patterns": attr.string_list(
        default = ["*.c", "*.h", "*.cc", "*.cpp"],
        doc = "Filename patterns for format checking",
    ),
    "exclude_patterns": attr.string_list(
        doc = "Filename patterns to exclude from format checking",
    ),
    "mode": attr.string(
        default = "diff",
        values = ["diff", "fix"],
        doc = "Execution mode: display diffs or fix formatting",
    ),
    "diff_command": attr.string(
        default = "diff -u",
        doc = "Command to execute to display diffs",
    ),
    "clang_format_command": attr.string(
        default = "clang-format",
        doc = "The clang-format executable",
    ),
    "workspace": attr.label(
        allow_single_file = True,
        doc = "Label of the WORKSPACE file",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:clang_format.template.sh",
        allow_single_file = True,
    ),
}

clang_format_fix = rule(
    implementation = _clang_format_impl,
    attrs = clang_format_attrs,
    executable = True,
)

_clang_format_test = rule(
    implementation = _clang_format_impl,
    attrs = clang_format_attrs,
    test = True,
)

def clang_format_check(**kwargs):
    tags = kwargs.get("tags", [])

    # Note: the "external" tag is a workaround for bazelbuild#15516.
    kwargs["tags"] = _ensure_tag(tags, "no-sandbox", "no-cache", "external")
    _clang_format_test(**kwargs)

################################################################################
# protolint
################################################################################
def _protolint_impl(ctx):
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    exclude_patterns = ["\\! -path {}".format(shell.quote(p)) for p in ctx.attr.exclude_patterns]
    include_patterns = ["-name {}".format(shell.quote(p)) for p in ctx.attr.patterns]
    workspace = ctx.file.workspace.path if ctx.file.workspace else ""
    substitutions = {
        "@@EXCLUDE_PATTERNS@@": " ".join(exclude_patterns),
        "@@INCLUDE_PATTERNS@@": " -o ".join(include_patterns),
        "@@PROTOLINT@@": shell.quote(ctx.executable.protolint.short_path),
        "@@MODE@@": shell.quote(ctx.attr.mode),
        "@@WORKSPACE@@": workspace,
    }
    ctx.actions.expand_template(
        template = ctx.file._runner,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    runfiles = [ctx.executable.protolint]
    if ctx.file.workspace:
        runfiles.append(ctx.file.workspace)

    return DefaultInfo(
        files = depset([out_file]),
        runfiles = ctx.runfiles(files = runfiles),
        executable = out_file,
    )
    return

protolint_attrs = {
    "patterns": attr.string_list(
        default = ["*.proto"],
        doc = "Filename patterns for format checking.",
    ),
    "exclude_patterns": attr.string_list(
        doc = "Filename patterns to exlucde from format checking.",
    ),
    "mode": attr.string(
        default = "diff",
        values = ["diff", "fix"],
        doc = "Execution mode: display diffs or fix formatting.",
    ),
    "protolint": attr.label(
        default = "@protolint//:protolint",
        allow_single_file = True,
        cfg = "host",
        executable = True,
        doc = "The protolint executable.",
    ),
    "workspace": attr.label(
        allow_single_file = True,
        doc = "Label of the WORKSPACE file",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:protolint.template.sh",
        allow_single_file = True,
    ),
}

protolint_fix = rule(
    implementation = _protolint_impl,
    attrs = protolint_attrs,
    executable = True,
)

_protolint_test = rule(
    implementation = _protolint_impl,
    attrs = protolint_attrs,
    test = True,
)

def protolint_check(**kwargs):
    tags = kwargs.get("tags", [])

    # Note: the "external" tag is a workaround for bazelbuild#15516.
    kwargs["tags"] = _ensure_tag(tags, "no-sandbox", "no-cache", "external")
    _protolint_test(**kwargs)
