# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# lowRISC opentitan, linters, and release process.
load("//third_party/lowrisc:repos.bzl", "lowrisc_repos")
lowrisc_repos()

# Release process.
load("@lowrisc_bazel_release//:repos.bzl", "lowrisc_bazel_release_repos")
lowrisc_bazel_release_repos()
load("@lowrisc_bazel_release//:deps.bzl", "lowrisc_bazel_release_deps")
lowrisc_bazel_release_deps()

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

# Various linters.
load("//third_party/lint:repos.bzl", "lint_repos")
lint_repos()

# Docker rules.
load("//third_party/docker:repos.bzl", "docker_repos")
docker_repos()
load("//third_party/docker:deps.bzl", "docker_deps")
docker_deps()

# Setup for linking in externally vendor customizations.
load("//rules:vendor.bzl", "vendor_repo_setup")
vendor_repo_setup(
    name = "vendor_setup",
    dummy = "src/vendor",
)
load("@vendor_setup//:repos.bzl", "vendor_repo")
vendor_repo(name = "vendor_repo")

