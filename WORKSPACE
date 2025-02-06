# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# lowRISC opentitan, linters, and release process.
load("//third_party/lowrisc:repos.bzl", "lowrisc_repos")
lowrisc_repos()

# Setup for linking in externally managed provisioning customizations for both
# secure/non-secure manufacturer domains.
load("@lowrisc_opentitan//rules:hooks_setup.bzl", "provisioning_exts_setup")
provisioning_exts_setup(
    name = "provisioning_exts_setup",
    dummy = "third_party/lowrisc/provisioning_exts",
)

# Declare the external repository for provisioning source code extensions.
load("@provisioning_exts_setup//:repos.bzl", "provisioning_exts_repo")
provisioning_exts_repo(name = "provisioning_exts")

# Python Toolchain + PIP Dependencies from the lowrisc_opentitan repo.
load("@lowrisc_opentitan//third_party/python:repos.bzl", "python_repos")
python_repos()
load("@lowrisc_opentitan//third_party/python:deps.bzl", "python_deps")
python_deps()
load("@lowrisc_opentitan//third_party/python:pip.bzl", "pip_deps")
pip_deps()
load("@lowrisc_opentitan//third_party/python:requirements.bzl", install_ot_python_deps="install_deps")
install_ot_python_deps(local_wheels_repo_target = "@ot_python_wheels//:sanitized_requirements.txt")

# Release process.
load("@lowrisc_bazel_release//:repos.bzl", "lowrisc_bazel_release_repos")
lowrisc_bazel_release_repos()
load("@lowrisc_bazel_release//:deps.bzl", "lowrisc_bazel_release_deps")
lowrisc_bazel_release_deps()

# Linters.
# The linter deps need to be loaded like this to get the python and PIP
# dependencies established in the proper order.
load("@lowrisc_misc_linters//rules:repos.bzl", "lowrisc_misc_linters_repos")
lowrisc_misc_linters_repos()
load("@lowrisc_misc_linters//rules:deps.bzl", "lowrisc_misc_linters_dependencies")
lowrisc_misc_linters_dependencies()
load("@lowrisc_misc_linters//rules:pip.bzl", "lowrisc_misc_linters_pip_dependencies")
lowrisc_misc_linters_pip_dependencies()
load("@lowrisc_misc_linters_pip//:requirements.bzl", install_lowrisc_lint_python_deps="install_deps")
install_lowrisc_lint_python_deps()

# Rust Toolchain + crates.io dependencies from the lowrisc_opentitan repo.
load("@lowrisc_opentitan//third_party/rust:repos.bzl", "rust_repos")
rust_repos()
load("@lowrisc_opentitan//third_party/rust:deps.bzl", "rust_deps")
rust_deps()
load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")
crate_universe_dependencies(bootstrap = True)
load("@lowrisc_opentitan//third_party/rust/crates:crates.bzl", "crate_repositories")
crate_repositories()

# HyperDebug firmware (required for opentitanlib) from the lowrisc_opentitan repo.
load("@lowrisc_opentitan//third_party/hyperdebug:repos.bzl", "hyperdebug_repos")
hyperdebug_repos()

# OpenOCD (required for opentitanlib) from the lowrisc_opentitan repo.
load("@lowrisc_opentitan//third_party/openocd:repos.bzl", "openocd_repos")
openocd_repos()

# SPHINCS+ Test Vectors (required for opentitanlib).
load("@lowrisc_opentitan//third_party/sphincsplus:repos.bzl", "sphincsplus_repos")
sphincsplus_repos()

# CRT is the Compiler Repository Toolkit.  It contains the configuration for
# the windows compiler.
load("//third_party/crt:repos.bzl", "crt_repos")
crt_repos()
load("@crt//:repos.bzl", "crt_repos")
crt_repos()
load("@crt//:deps.bzl", "crt_deps")
crt_deps()
load("@crt//config:registration.bzl", "crt_register_toolchains")
crt_register_toolchains(
    riscv32 = True,
    win32 = True,
    win64 = True,
)

# Go dependencies.
# gazelle:repository_macro third_party/go/deps.bzl%go_packages_
load("//third_party/go:repos.bzl", "go_repos")
go_repos()
load("//third_party/go:deps.bzl", "go_deps")
go_deps()

# Google dependencies.
# BoringSSL, RE2, GoogleTest, Protobuf Matchers, ABSL.
load("//third_party/google:repos.bzl", "google_repos")
google_repos()

# Protobuf rules.
load("//third_party/protobuf:repos.bzl", "protobuf_repos")
protobuf_repos()
# Load the proto deps in the right order
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()

# Various linters.
load("//third_party/lint:repos.bzl", "lint_repos")
lint_repos()

# Foreign CC and packaging/release rules.
load("//third_party/bazel:repos.bzl", "bazel_repos")
bazel_repos()
load("//third_party/bazel:deps.bzl", "bazel_deps")
bazel_deps()

# SoftHSM2.
load("//third_party/softhsm2:repos.bzl", "softhsm2_repos")
softhsm2_repos()

# Docker rules.
load("//third_party/docker:repos.bzl", "docker_repos")
docker_repos()
load("//third_party/docker:deps.bzl", "docker_deps")
docker_deps()
