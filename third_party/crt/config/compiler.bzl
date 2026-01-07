# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//third_party/crt/config:features.bzl", "FeatureSetInfo", "feature_set_subst")
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "artifact_name_pattern",
    "tool_path",
)
load("@rules_cc//cc:defs.bzl", "cc_toolchain")

PARAM_DEFAULTS = {
    "host_system_name": "x86_64-unknown-linux-gnu",
    "target_system_name": "unknown",
    "target_libc": "unknown",
    "compiler": "unknown",
    "abi_version": "unknown",
    "abi_libc_version": "unknown",
}

# This provider wraps the opaque artifact_name_pattern object so it can be passed
# from the 'artifact_name' rule to the 'toolchain_config' rule.
ArtifactNamePatternInfo = provider(
    fields = ["pattern"],
    doc = "Wraps an artifact_name_pattern object for passing between rules.",
)

def listify_flags(flag, args = [], spaces_in_args = False):
    args = [flag.format(p) for p in args]
    value = "|".join(args)
    if not spaces_in_args:
        value = value.replace(" ", "|")
    return value

def union(*args, **kwargs):
    d = {}
    for a in args:
        d.update(a)
    d.update(kwargs)
    return d

def _toolchain_config_impl(ctx):
    tool_paths = [
        tool_path(name = k, path = v)
        for k, v in ctx.attr.tools.items()
    ]
    params = dict(**PARAM_DEFAULTS)
    params.update(ctx.attr.params)
    features = feature_set_subst(ctx.attr.feature_set[FeatureSetInfo], **ctx.attr.substitutions)
    artifact_name_patterns = [a[ArtifactNamePatternInfo].pattern for a in ctx.attr.artifact_naming]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = ctx.attr.toolchain_identifier,
        target_cpu = ctx.attr.architecture,
        cxx_builtin_include_directories = ctx.attr.include_directories,
        host_system_name = params["host_system_name"],
        target_system_name = params["target_system_name"],
        target_libc = params["target_libc"],
        compiler = params["compiler"],
        abi_version = params["abi_version"],
        abi_libc_version = params["abi_libc_version"],
        tool_paths = tool_paths,
        features = features.values(),
        artifact_name_patterns = artifact_name_patterns,
    )

toolchain_config = rule(
    implementation = _toolchain_config_impl,
    attrs = {
        "architecture": attr.string(doc = "Target architecture"),
        "artifact_naming": attr.label_list(providers = [ArtifactNamePatternInfo], doc = "Naming conventions"),
        "feature_set": attr.label(providers = [FeatureSetInfo], doc = "Features of this toolchain"),
        "substitutions": attr.string_dict(doc = "Substitutions for the feature_set"),
        "tools": attr.string_dict(doc = "Mapping of tool names to their wrapper paths"),
        "toolchain_identifier": attr.string(
            mandatory = True,
            doc = "Indentifier used by the toolchain, this should be consistent with the cc_toolchain rule attribute",
        ),
        "include_directories": attr.string_list(doc = "Compiler-specific include directories"),
        "params": attr.string_dict(doc = "Toolchain config parameters", default = {}),
    },
    provides = [CcToolchainConfigInfo],
)

def _artifact_name_impl(ctx):
    return [ArtifactNamePatternInfo(pattern = artifact_name_pattern(
        category_name = ctx.attr.category,
        prefix = ctx.attr.prefix,
        extension = ctx.attr.extension,
    ))]

artifact_name = rule(
    implementation = _artifact_name_impl,
    attrs = {
        "category": attr.string(mandatory = True, doc = "The category of artifacts that this selection applies to."),
        "prefix": attr.string(doc = "The prefix for creating the artifact for this selection."),
        "extension": attr.string(doc = "The extension for creating the artifact for this selection."),
    },
    provides = [ArtifactNamePatternInfo],
)

def setup(
        name,
        architecture,
        artifact_naming,
        feature_set,
        tools,
        compiler_components,
        include_directories,
        constraints,
        isystem = "-isystem{}",
        substitutions = {},
        params = {}):
    subst = {
        "[SYSTEM_INCLUDES]": listify_flags(isystem, include_directories),
    }
    subst.update(substitutions)

    toolchain_config(
        name = name + "_config",
        architecture = architecture,
        artifact_naming = artifact_naming,
        feature_set = feature_set,
        tools = tools,
        toolchain_identifier = name,
        include_directories = include_directories,
        params = params,
        substitutions = subst,
    )

    cc_toolchain(
        name = name,
        all_files = compiler_components,
        compiler_files = compiler_components,
        dwp_files = compiler_components,
        linker_files = compiler_components,
        objcopy_files = compiler_components,
        strip_files = compiler_components,
        as_files = compiler_components,
        ar_files = compiler_components,
        supports_param_files = False,
        toolchain_config = ":{}_config".format(name),
    )

    native.toolchain(
        name = "cc_toolchain_" + name,
        exec_compatible_with = [
            "@platforms//cpu:x86_64",
        ],
        target_compatible_with = constraints,
        toolchain = ":" + name,
        toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    )
