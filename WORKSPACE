# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# lowRISC linters and release process.
load("//third_party/lowrisc:repos.bzl", "lowrisc_repos")
lowrisc_repos()
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
    win32 = True,
    win64 = True,
)

# Google dependencies.
# BoringSSL, RE2, GoogleTest, Protobuf Matchers, ABSL.
load("//third_party/google:repos.bzl", "google_repos")
google_repos()

# gazelle:repository_macro third_party/go/deps.bzl%go_packages_
load("//third_party/go:repos.bzl", "go_repos")
go_repos()
load("//third_party/go:deps.bzl", "go_deps")
go_deps()

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
load("//third_party/softhsm2:deps.bzl", "softhsm2_deps")
softhsm2_deps()

# Docker rules.
load("//third_party/docker:repos.bzl", "docker_repos")
docker_repos()
load("//third_party/docker:deps.bzl", "docker_deps")
docker_deps()
