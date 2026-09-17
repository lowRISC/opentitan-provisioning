# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# Base image for the simulated Windows ATE machine.
#
# In production the ATE client is a Windows host that loads `ate.dll` and talks
# to the provisioning appliance over the network. This image stands in for that
# host: a Wine runtime with a pre-initialized prefix, and nothing else. The
# Windows artifacts themselves are layered on top at test time by
# `Dockerfile.bundle`, so that rebuilding the DLL does not rebuild Wine.
FROM debian:trixie-slim

LABEL version="1.0"
LABEL description="OpenTitan provisioning Windows ATE client (Wine) container."

# Everything runs as root: rootless podman without a subuid range maps a single
# uid into the container, so apt's privilege separation (and any other user
# switch) fails with EPERM.
RUN echo 'APT::Sandbox::User "root";' > /etc/apt/apt.conf.d/00-no-sandbox

# Wine needs the i386 architecture to run the 32-bit MinGW artifacts, so enable
# multiarch before installing.
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        wine \
        wine32:i386 \
    && rm -rf /var/lib/apt/lists/*

ENV WINEPREFIX=/opt/wineprefix
ENV WINEDEBUG=-all
# Neither Mono nor Gecko is needed; suppress the interactive install prompts.
ENV WINEDLLOVERRIDES="mscoree,mshtml="
# wineserver needs a writable runtime directory; the image has no logged-in
# user, so point it at a scratch location.
ENV XDG_RUNTIME_DIR=/run/wine
RUN mkdir -p /run/wine && chmod 700 /run/wine


# Initialize the prefix at build time so the first test run does not pay for it
# (prefix creation takes tens of seconds).
RUN wineboot --init \
    && wineserver --wait

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

WORKDIR /opt/ate
ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
