#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Helpers for running Win32 ATE artifacts inside the simulated Windows ATE
# machine container (see util/containers/ate_client/).
#
# The container stands in for a real Windows ATE host: it holds the Wine
# runtime plus an installed copy of the Windows release bundle, and reaches the
# provisioning appliance over the network like any other client. Nothing
# Windows-specific needs to be installed on the host running the tests.
#
# Sourced by:
#   - src/ate/test_programs/run_ate_dll_smoke_test.sh (hermetic bazel test)
#   - tests/run_ate_dll_test.sh                       (integration test)

# Image holding just the Wine runtime. Rarely changes, so it is cached across
# runs and, eventually, pulled from the registry instead of being rebuilt.
readonly ATE_CLIENT_BASE_IMAGE="${ATE_CLIENT_BASE_IMAGE:-us-docker.pkg.dev/opentitan/opentitan-public/ot-prov-ate-client:latest}"
# Image holding the Wine runtime plus the bundle under test. Rebuilt every run;
# only the final COPY layer is invalidated.
readonly ATE_CLIENT_IMAGE="${ATE_CLIENT_IMAGE:-localhost/ate_client:latest}"
# Filename the harness is installed under inside the image. Must match the
# default in util/containers/ate_client/entrypoint.sh.
readonly ATE_CLIENT_HARNESS_EXE="ate_dll_smoke.exe"

# Fails unless podman is available.
ate_client_require_podman() {
  if ! command -v podman >/dev/null 2>&1; then
    echo "ERROR: 'podman' not found in PATH."
    echo "Please install via 'sudo apt install podman'."
    return 1
  fi
}

# ate_client_build_base_image <repo_top>
#
# Builds the Wine base image unconditionally. Use this to pick up Dockerfile
# changes; `ate_client_ensure_base_image` will not rebuild an image that
# already exists.
ate_client_build_base_image() {
  local repo_top="$1"

  podman build -t "${ATE_CLIENT_BASE_IMAGE}" \
    -f "${repo_top}/util/containers/ate_client/Dockerfile" \
    "${repo_top}/util/containers/ate_client"
}

# ate_client_ensure_base_image <repo_top>
#
# Builds the Wine base image if it is not already in the local registry.
ate_client_ensure_base_image() {
  local repo_top="$1"

  if podman image exists "${ATE_CLIENT_BASE_IMAGE}"; then
    echo "Using cached base image ${ATE_CLIENT_BASE_IMAGE}."
    return 0
  fi
  echo "Base image ${ATE_CLIENT_BASE_IMAGE} not found; building it (slow, once)."
  ate_client_build_base_image "${repo_top}"
}

# ate_client_stage_bundle <context_dir> <harness_exe> <ate_dll>
#
# Lays out the Windows bundle that gets installed into the container image.
# Because ate.dll links its C++/threading runtime statically, only the harness
# executable and ate.dll are staged into the container directory.
ate_client_stage_bundle() {
  local context_dir="$1"
  local harness_exe="$2"
  local ate_dll="$3"

  if [[ -z "${context_dir}" ]]; then
    echo "ERROR: ate_client_stage_bundle called with an empty context dir."
    return 1
  fi
  rm -rf "${context_dir}"
  mkdir -p "${context_dir}/bundle"
  cp -f "${harness_exe}" "${context_dir}/bundle/${ATE_CLIENT_HARNESS_EXE}"
  cp -f "${ate_dll}" "${context_dir}/bundle/ate.dll"
  chmod u+w "${context_dir}/bundle"/*.exe "${context_dir}/bundle"/*.dll
}

# ate_client_build_image <repo_top> <context_dir>
#
# Installs the staged bundle onto the base image.
ate_client_build_image() {
  local repo_top="$1"
  local context_dir="$2"

  cp -f "${repo_top}/util/containers/ate_client/Dockerfile.bundle" \
    "${context_dir}/Dockerfile"
  podman build -t "${ATE_CLIENT_IMAGE}" \
    --build-arg "BASE_IMAGE=${ATE_CLIENT_BASE_IMAGE}" \
    -f "${context_dir}/Dockerfile" "${context_dir}"
}

# ate_client_run <network> <certs_dir> [harness_arg...]
#
# Runs the harness inside the container. <network> is a podman network mode:
# `none` when no appliance is involved, `bridge` to reach one over a real
# network interface, or `host` to share the host's network namespace.
# <certs_dir> is bind mounted read-only at /opt/ate/certs; pass an empty string
# to skip it.
ate_client_run() {
  local network="$1"
  local certs_dir="$2"
  shift 2

  local -a args=(
    run --rm
    --network="${network}"
    --name "ate-client-$$"
  )
  if [[ -n "${certs_dir}" ]]; then
    args+=(--volume "${certs_dir}:/opt/ate/certs:ro")
  fi
  args+=("${ATE_CLIENT_IMAGE}" "$@")

  podman "${args[@]}"
}

# Exit status the harness uses for an unhandled exception. Must match
# `kCrashExitCode` in src/ate/test_programs/ate_dll_smoke.cc.
readonly ATE_CLIENT_CRASH_STATUS=42

# ate_client_report_status <case_name> <exit_status>
#
# Translates the harness exit status into a readable verdict. Returns non-zero
# when the case failed.
ate_client_report_status() {
  local name="$1"
  local status="$2"

  if [[ "${status}" -eq 0 ]]; then
    echo "PASS[${name}]"
    return 0
  fi
  if [[ "${status}" -eq "${ATE_CLIENT_CRASH_STATUS}" ]]; then
    echo "FAIL[${name}]: ate.dll took an unhandled exception (access violation)."
    echo "  Known 32-bit MinGW toolchain hazard: gRPC's channel setup has been"
    echo "  miscompiled by this toolchain before."
  else
    echo "FAIL[${name}]: ${ATE_CLIENT_HARNESS_EXE} exited with status ${status}."
  fi
  return 1
}
