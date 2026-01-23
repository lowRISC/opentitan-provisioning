# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Use Debian Sid (Unstable) which ships with OpenSSL 3.4+
FROM debian:sid-slim

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
# Note: this commit hash should be kept in sync with that in MODULE.bazel
ARG SOFTHSM2_COMMIT_HASH=5fe2207418cd066142d122ea2c0c67f7831b6a63
RUN cd /opt && \
      git clone https://github.com/antoinelochet/SoftHSMv2.git && \
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
          --enable-mldsa \
          --disable-p11-kit \
          --with-crypto-backend=openssl \
          --localstatedir=/opt/SoftHSMv2 \
          --sysconfdir=/opt/SoftHSMv2 \
          --bindir=/opt/SoftHSMv2 && \
      make install

ENTRYPOINT [ "/usr/bin/bash", "-c" ]
