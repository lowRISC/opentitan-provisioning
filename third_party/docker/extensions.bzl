# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@io_bazel_rules_docker//container:pull.bzl", "container_pull")
load("@io_bazel_rules_docker//toolchains/docker:toolchain.bzl", "toolchain_configure")

def _docker_extension_impl(ctx):
    toolchain_configure(
        name = "docker_config",
        docker_path = "/usr/bin/podman",
    )

    container_pull(
        name = "go_image_base",
        registry = "gcr.io",
        repository = "distroless/base",
        tag = "debug",
    )

    container_pull(
        name = "go_image_static",
        registry = "gcr.io",
        repository = "distroless/static",
        tag = "latest",
    )

    container_pull(
        name = "container_k8s_pause",
        registry = "k8s.gcr.io",
        repository = "pause",
        digest = "sha256:369201a612f7b2b585a8e6ca99f77a36bcdbd032463d815388a96800b63ef2c8",
        tag = "3.5",
    )

    container_pull(
        name = "container_softhsm2",
        registry = "us-docker.pkg.dev/opentitan/opentitan-public",
        repository = "ot-prov-softhsm2",
        digest = "sha256:b7da668a27ffe47a7da34a476bbb2acf59ac390cb9f7b166d76aa437c61088d6",
        tag = "latest",
    )

docker_extension = module_extension(
    implementation = _docker_extension_impl,
)
