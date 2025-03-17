# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Docker container used to build and run SoftHSM2.

FROM ubuntu:22.04
LABEL version="1.0"
LABEL description="OpenTitan provisioning SoftHSM2 container."

# Install system packages.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        flex \
        g++ \
        git \
        libssl-dev \
        lsb-release \
        make \
        libtool \
        pkg-config

# Set Locale to utf-8 everywhere.
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en

# Clone SoftHSM2.
# Note: this commit hash should be kept in sync with that in:
# third_party/softhsm2/deps.bzl
ARG SOFTHSM2_COMMIT_HASH=4975c0df4c7090e97a3860ae21079a9597cfedc6
RUN cd /opt && \
      git clone https://github.com/opendnssec/SoftHSMv2.git && \
      cd SoftHSMv2 && \
      git reset --hard ${SOFTHSM2_COMMIT_HASH}

# Apply patches.
COPY 0001-Disable-filename-logging.patch /tmp/
RUN cd /opt/SoftHSMv2/ && for p in $(ls /tmp/*.patch); do git apply ${p}; done

# Build SoftHSM2.
RUN cd /opt/SoftHSMv2 && \
      ./autogen.sh && \
      ./configure \
          --enable-ecc \
          --disable-p11-kit \
          --disable-p11-kit \
          --with-crypto-backend=openssl \
          --localstatedir=/opt/SoftHSMv2 \
          --sysconfdir=/opt/SoftHSMv2 \
          --bindir=/opt/SoftHSMv2 && \
      make install

ENTRYPOINT [ "/usr/bin/bash", "-c" ]
