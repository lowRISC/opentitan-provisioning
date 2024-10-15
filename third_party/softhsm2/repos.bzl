# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@//rules:repo.bzl", "http_archive_or_local")

SOFTHSM2_COMMIT_HASH = "4975c0df4c7090e97a3860ae21079a9597cfedc6"

def softhsm2_repos(local = None):
    http_archive_or_local(
        name = "softhsm2",
        local = local,
        build_file = Label("//third_party/softhsm2:BUILD.softhsm2.bazel"),
        url = "https://github.com/opendnssec/SoftHSMv2/archive/{}.tar.gz".format(SOFTHSM2_COMMIT_HASH),
        strip_prefix = "SoftHSMv2-{}".format(SOFTHSM2_COMMIT_HASH),
        sha256 = "72cf979ec4f74ca4555861dcae45cf7d1b667cc2e4f3ee3fb26e6ff1b99aec95",
        patches = [
            Label("//util/containers/softhsm2:0001-Disable-filename-logging.patch"),
            Label("//util/containers/softhsm2:0002-Implement-PKCS-11-HKDF-key-derivation.patch"),
        ],
        patch_args = ["-p1"],
    )
