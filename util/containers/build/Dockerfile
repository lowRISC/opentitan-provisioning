# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Docker container used for development.

FROM ubuntu:22.04
LABEL version="1.0"
LABEL description="OpenTitan provisioning development container."
LABEL maintainer="moidx@opentitan.org"

# Use bash as default shell.
RUN ln -sf /bin/bash /bin/sh

# Install system packages
#
# Install (and cleanup) required packages (from apt-requirements.txt).
# Also add some additional packages for the use within this container and for
# developer convenience:
# - gosu and sudo are used by the scripting to make the image more convenient
#   to use.
# - locales and locales-all are required to set the locale.
# - minicom and screen are useful to see UART communication.
COPY apt-requirements.txt /tmp/apt-requirements.txt
RUN apt-get update \
    && sed -i -e '/^$/d' -e '/^#/d' -e 's/#.*//' /tmp/apt-requirements.txt \
    && DEBIAN_FRONTEND=noninteractive xargs apt-get install -y --no-install-recommends </tmp/apt-requirements.txt \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        sudo \
        gosu \
        locales \
        locales-all \
        minicom \
        screen \
        openssl \
    && apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

# Set Locale to utf-8 everywhere
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en

# Configure bazelisk
RUN go install github.com/bazelbuild/bazelisk@latest
ENV PATH ${PATH}:/root/go/bin

ENTRYPOINT [ "/usr/bin/bash", "-c" ]
