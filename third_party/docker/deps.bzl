# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@io_bazel_rules_docker//container:pull.bzl", "container_pull")
load("@io_bazel_rules_docker//go:image.bzl", _go_image_repos = "repositories")
load("@io_bazel_rules_docker//repositories:deps.bzl", "deps")
load("@io_bazel_rules_docker//repositories:repositories.bzl", "repositories")
load(
    "@io_bazel_rules_docker//toolchains/docker:toolchain.bzl",
    docker_toolchain_configure = "toolchain_configure",
)

def docker_deps():
    docker_toolchain_configure(
        name = "docker_config",
        docker_path = "/usr/bin/podman",
    )

    repositories()
    deps()
    _go_image_repos()

    container_pull(
        name = "container_etcd",
        registry = "gcr.io/etcd-development",
        digest = "sha256:9344cfb9cbe4df0635478b6a2b62765330128fbdf3ca8fc9f2edac262552f700",
        repository = "etcd",
        tag = "v3.5.5",
    )

    container_pull(
        name = "container_nginx",
        registry = "index.docker.io",
        digest = "sha256:baa881b012a49e3c2cd6ab9d80f9fcd2962a98af8ede947d0ef930a427b28afc",
        repository = "nginx",
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
