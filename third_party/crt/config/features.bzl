# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    __feature = "feature",
    __flag_group = "flag_group",
    __flag_set = "flag_set",
    __with_feature_set = "with_feature_set",
)
load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")

with_feature_set = __with_feature_set

CPP_ALL_COMPILE_ACTIONS = [
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.lto_backend,
    ACTION_NAMES.clif_match,
]

C_ALL_COMPILE_ACTIONS = [
    ACTION_NAMES.assemble,
    ACTION_NAMES.c_compile,
]

LD_ALL_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

FeatureSetInfo = provider(fields = ["features", "subst"])

# This provider wraps the feature configuration so it can be passed from the 'feature'
# rule to the 'feature_set' rule.
FeatureInfo = provider(
    fields = ["feature_config"],
    doc = "Wraps a C++ feature configuration object for passing between rules.",
)

def reify_flag_group(
        flags = [],
        flag_groups = [],
        iterate_over = None,
        expand_if_available = None,
        expand_if_not_available = None,
        expand_if_true = None,
        expand_if_false = None,
        expand_if_equal = None,
        type_name = None,
        subst = {}):
    flags2 = []
    for f in flags:
        if f in subst:
            if f.startswith("[") and f.endswith("]"):
                flags2.extend(subst[f].split("|"))
        else:
            for k, v in subst.items():
                f = f.replace(k, v)
            flags2.append(f)

    return __flag_group(
        flags2,
        flag_groups,
        iterate_over,
        expand_if_available,
        expand_if_not_available,
        expand_if_true,
        expand_if_false,
        expand_if_equal,
    )

def reify_with_features_set(
        features,
        not_features,
        type_name):
    if type_name != "with_feature_set":
        fail("the argument to with_features must be an array of values created by with_feature_set")
    return with_feature_set(
        features,
        not_features,
    )

def reify_flag_set(
        actions = [],
        with_features = [],
        flag_groups = [],
        type_name = None):
    return __flag_set(
        actions,
        with_features = [reify_with_features_set(**v) for v in with_features],
        flag_groups = [reify_flag_group(**v) for v in flag_groups],
    )

def feature_set_subst(fs, **kwargs):
    subst = dict(fs.subst)
    subst.update(kwargs)
    features = {}
    for name, feature in fs.features.items():
        flag_sets = [
            __flag_set(
                f.actions,
                f.with_features,
                [
                    reify_flag_group(
                        g.flags,
                        g.flag_groups,
                        g.iterate_over,
                        g.expand_if_available,
                        g.expand_if_not_available,
                        g.expand_if_true,
                        g.expand_if_false,
                        g.expand_if_equal,
                        subst = subst,
                    )
                    for g in f.flag_groups
                ],
            )
            for f in feature.flag_sets
        ]
        features[name] = __feature(
            name = feature.name,
            enabled = feature.enabled,
            flag_sets = flag_sets,
            requires = feature.requires,
            implies = feature.implies,
            provides = feature.provides,
        )
    return features

def flag_group(
        flags = [],
        flag_groups = [],
        iterate_over = None,
        expand_if_available = None,
        expand_if_not_available = None,
        expand_if_true = None,
        expand_if_false = None,
        expand_if_equal = None):
    return {
        "flags": flags,
        "flag_groups": flag_groups,
        "iterate_over": iterate_over,
        "expand_if_available": expand_if_available,
        "expand_if_not_available": expand_if_not_available,
        "expand_if_true": expand_if_true,
        "expand_if_false": expand_if_false,
        "expand_if_equal": expand_if_equal,
    }

def flag_set(
        actions = [],
        with_features = [],
        flag_groups = []):
    return json.encode({
        "actions": actions,
        "with_features": with_features,
        "flag_groups": flag_groups,
    })

def _feature_impl(ctx):
    f = __feature(
        name = ctx.attr.name,
        enabled = ctx.attr.enabled,
        flag_sets = [reify_flag_set(**json.decode(v)) for v in ctx.attr.flag_sets],
        requires = ctx.attr.requires,
        implies = ctx.attr.implies,
        provides = ctx.attr.provides,
    )
    return [
        FeatureInfo(feature_config = f),
    ]

feature = rule(
    implementation = _feature_impl,
    attrs = {
        "enabled": attr.bool(mandatory = True, doc = "Whether the feature is enabled."),
        "flag_sets": attr.string_list(default = [], doc = "Flag sets for this feature."),
        "requires": attr.string_list(default = [], doc = "A list of feature sets defining when this feature is supported by the toolchain."),
        "implies": attr.string_list(default = [], doc = "A string list of features or action configs that are automatically enabled when this feature is enabled."),
        "provides": attr.string_list(default = [], doc = "A list of names this feature conflicts with."),
    },
    provides = [FeatureInfo],
)

def feature_single_flag_c_cpp(name, flag, c_only = False, enabled = True):
    """This macro produces a C/C++ feature() that enables a single flag."""
    feature(
        name = name,
        enabled = enabled,
        flag_sets = [
            flag_set(
                actions = C_ALL_COMPILE_ACTIONS + ([] if c_only else CPP_ALL_COMPILE_ACTIONS),
                flag_groups = [
                    flag_group(
                        flags = [flag],
                    ),
                ],
            ),
        ],
    )

def _feature_set_impl(ctx):
    features = {}
    subst = {}
    for base in ctx.attr.base:
        features.update(base[FeatureSetInfo].features)
        subst.update(base[FeatureSetInfo].subst)
    for feature in ctx.attr.feature:
        # Unwrap the feature from FeatureInfo
        f = feature[FeatureInfo].feature_config
        features[f.name] = f
    subst.update(ctx.attr.substitutions)

    #print(json.encode_indent(features))
    return [
        FeatureSetInfo(features = features, subst = subst),
    ]

feature_set = rule(
    implementation = _feature_set_impl,
    attrs = {
        "base": attr.label_list(default = [], providers = [FeatureSetInfo], doc = "A base feature set to derive a new set"),
        "feature": attr.label_list(mandatory = True, providers = [FeatureInfo], doc = "A list of features in this set"),
        "substitutions": attr.string_dict(doc = "Substitutions to apply to features"),
    },
    provides = [FeatureSetInfo],
)
