# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "artifact_name_pattern",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)

ALL_COMPILE_ACTIONS = [
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.lto_backend,
    ACTION_NAMES.clif_match,
]

LD_ALL_ACTIONS = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _cc_toolchain_config_impl(ctx):
    tool_paths = [
        tool_path(name = "ar", path = "wrappers/ar"),
        tool_path(name = "cpp", path = "wrappers/cpp"),
        tool_path(name = "gcc", path = "wrappers/gcc"),
        tool_path(name = "gcov", path = "wrappers/gcov"),
        tool_path(name = "ld", path = "wrappers/ld"),
        tool_path(name = "nm", path = "wrappers/nm"),
        tool_path(name = "objcopy", path = "wrappers/objcopy"),
        tool_path(name = "objdump", path = "wrappers/objdump"),
        tool_path(name = "strip", path = "wrappers/strip"),
    ]

    default_compile_flags = feature(
        name = "default_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-Wall",
                            "-Wextra",
                            "-Wno-unused-parameter",
                            "-Wno-missing-field-initializers",
                            "-Wno-sign-compare",
                            "-Werror=date-time",
                            "-ffunction-sections",
                            "-fdata-sections",
                            # 32-bit Windows callers (MSVC / LabVIEW / TestStand ATE hosts) only
                            # guarantee 4-byte stack alignment (ESP % 4 == 0) on DLL entry, whereas
                            # Clang/MinGW assumes 16-byte alignment for SSE instructions.
                            "-mstackrealign",
                        ],
                    ),
                ],
            ),
        ],
    )

    default_link_flags = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = LD_ALL_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-Wl,--no-insert-timestamp",
                            "-Wl,--gc-sections",
                        ],
                    ),
                ],
            ),
        ],
    )

    dbg = feature(
        name = "dbg",
        enabled = False,
        flag_sets = [
            flag_set(
                actions = ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = ["-O0", "-g"],
                    ),
                ],
            ),
        ],
        provides = ["compilation_mode"],
    )

    fastbuild = feature(
        name = "fastbuild",
        enabled = False,
        flag_sets = [
            flag_set(
                actions = ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = ["-O1", "-g", "-DNDEBUG"],
                    ),
                ],
            ),
        ],
        provides = ["compilation_mode"],
    )

    opt = feature(
        name = "opt",
        enabled = False,
        flag_sets = [
            flag_set(
                actions = ALL_COMPILE_ACTIONS,
                flag_groups = [
                    flag_group(
                        flags = ["-O2", "-DNDEBUG"],
                    ),
                ],
            ),
        ],
        provides = ["compilation_mode"],
    )

    artifact_name_patterns = [
        artifact_name_pattern(
            category_name = "executable",
            prefix = "",
            extension = ".exe",
        ),
        artifact_name_pattern(
            category_name = "dynamic_library",
            prefix = "",
            extension = ".dll",
        ),
    ]

    cxx_builtin_include_directories = [
        "external/+_repo_rules+llvm_mingw_files/i686-w64-mingw32/include",
        "external/+_repo_rules+llvm_mingw_files/lib/clang",
        "external/_main~_repo_rules~llvm_mingw_files/i686-w64-mingw32/include",
        "external/_main~_repo_rules~llvm_mingw_files/lib/clang",
    ]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = "llvm_mingw_win32",
        target_cpu = "x86_32",
        host_system_name = "x86_64-unknown-linux-gnu",
        target_system_name = "i686-w64-mingw32",
        target_libc = "mingw",
        compiler = "clang",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
        features = [
            default_compile_flags,
            default_link_flags,
            dbg,
            fastbuild,
            opt,
        ],
        artifact_name_patterns = artifact_name_patterns,
        cxx_builtin_include_directories = cxx_builtin_include_directories,
    )

llvm_mingw_cc_toolchain_config = rule(
    implementation = _cc_toolchain_config_impl,
    attrs = {},
    provides = [CcToolchainConfigInfo],
)
