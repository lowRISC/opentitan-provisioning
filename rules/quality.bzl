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

def _general_lint_impl(ctx):
    out_file = ctx.actions.declare_file(ctx.label.name + ".bash")
    exclude_patterns = ["\\! -path {}".format(shell.quote(p)) for p in ctx.attr.exclude_patterns]
    include_patterns = ["-name {}".format(shell.quote(p)) for p in ctx.attr.patterns]
    workspace = ctx.file.workspace.path if ctx.file.workspace else ""
    substitutions = {
        "@@EXCLUDE_PATTERNS@@": " ".join(exclude_patterns),
        "@@INCLUDE_PATTERNS@@": " -o ".join(include_patterns),
        "@@LINT_TOOL@@": shell.quote(ctx.executable.lint_tool.short_path),
        "@@MODE@@": shell.quote(ctx.attr.mode),
        "@@WORKSPACE@@": workspace,
        "@@RUNNER_SH@@": ctx.file._runner.path,
    }
    ctx.actions.expand_template(
        template = ctx.file._runner_general,
        output = out_file,
        substitutions = substitutions,
        is_executable = True,
    )

    runfiles = [ctx.executable.lint_tool, ctx.file._runner]
    if ctx.file.workspace:
        runfiles.append(ctx.file.workspace)

    return DefaultInfo(
        files = depset([out_file]),
        runfiles = ctx.runfiles(files = runfiles),
        executable = out_file,
    )

################################################################################
# gofmt
################################################################################
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
    "lint_tool": attr.label(
        default = "@go_sdk//:bin/gofmt",
        allow_single_file = True,
        cfg = "host",
        executable = True,
        doc = "The gofmt executable",
    ),
    "workspace": attr.label(
        allow_single_file = True,
        doc = "Label of the WORKSPACE file",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:gofmt.sh",
        allow_single_file = True,
    ),
    "_runner_general": attr.label(
        default = "//rules/scripts:general_lint.template.sh",
        allow_single_file = True,
    ),
}

gofmt_fix = rule(
    implementation = _general_lint_impl,
    attrs = gofmt_attrs,
    executable = True,
)

_gofmt_test = rule(
    implementation = _general_lint_impl,
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
    "lint_tool": attr.label(
        default = "@clang-format//:clang-format",
        allow_single_file = True,
        cfg = "host",
        executable = True,
        doc = "The clang-format executable",
    ),
    "workspace": attr.label(
        allow_single_file = True,
        doc = "Label of the WORKSPACE file",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:clang_format.sh",
        allow_single_file = True,
    ),
    "_runner_general": attr.label(
        default = "//rules/scripts:general_lint.template.sh",
        allow_single_file = True,
    ),
}

clang_format_fix = rule(
    implementation = _general_lint_impl,
    attrs = clang_format_attrs,
    executable = True,
)

_clang_format_test = rule(
    implementation = _general_lint_impl,
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
    "lint_tool": attr.label(
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
        default = "//rules/scripts:protolint.sh",
        allow_single_file = True,
    ),
    "_runner_general": attr.label(
        default = "//rules/scripts:general_lint.template.sh",
        allow_single_file = True,
    ),
}

protolint_fix = rule(
    implementation = _general_lint_impl,
    attrs = protolint_attrs,
    executable = True,
)

_protolint_test = rule(
    implementation = _general_lint_impl,
    attrs = protolint_attrs,
    test = True,
)

def protolint_check(**kwargs):
    tags = kwargs.get("tags", [])

    # Note: the "external" tag is a workaround for bazelbuild#15516.
    kwargs["tags"] = _ensure_tag(tags, "no-sandbox", "no-cache", "external")
    _protolint_test(**kwargs)

################################################################################
# include guard
################################################################################
include_guard_attrs = {
    "patterns": attr.string_list(
        default = ["*.h"],
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
    "lint_tool": attr.label(
        default = "//util:fix_include_guard.py",
        allow_single_file = True,
        cfg = "host",
        executable = True,
        doc = "The include_guard.py tool.",
    ),
    "workspace": attr.label(
        allow_single_file = True,
        doc = "Label of the WORKSPACE file",
    ),
    "_runner": attr.label(
        default = "//rules/scripts:include_guard.sh",
        allow_single_file = True,
    ),
    "_runner_general": attr.label(
        default = "//rules/scripts:general_lint.template.sh",
        allow_single_file = True,
    ),
}

include_guard_fix = rule(
    implementation = _general_lint_impl,
    attrs = include_guard_attrs,
    executable = True,
)

_include_guard_test = rule(
    implementation = _general_lint_impl,
    attrs = include_guard_attrs,
    test = True,
)

def include_guard_check(**kwargs):
    tags = kwargs.get("tags", [])

    # Note: the "external" tag is a workaround for bazelbuild#15516.
    kwargs["tags"] = _ensure_tag(tags, "no-sandbox", "no-cache", "external")
    _include_guard_test(**kwargs)
