#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${REPO_TOP:=$(git rev-parse --show-toplevel)}"
: "${BAZEL_VERSION:=$(cat "${REPO_TOP}/.bazelversion")}"
: "${BAZEL_AIRGAPPED_DIR:=bazel-airgapped}"
: "${BAZEL_DISTDIR:=bazel-distdir}"
: "${BAZEL_CACHEDIR:=bazel-cache}"
: "${BAZEL_PYTHON_WHEEL_REPO:=ot_python_wheels}"

LINE_SEP="====================================================================="

################################################################################
# Process cmd line args.
################################################################################
function usage() {
  cat << USAGE
Utility script to prepare a directory with all bazel dependencies needed to
build project artifacts with bazel in an airgapped environment.

Usage: $0 [-c ALL | DISTDIR | CACHE]

  - c: airgapped directory contents, set to either ALL or DISTDIR or CACHE.
  - f: force rebuild of airgapped directory, overwriting any existing one.

Airgapped directory contents (-b):
  - ALL: both the distdir and cache will be added. (Default)
  - DISTDIR: only the distdir, containing bazel and its dependencies will be added.
  - CACHE: only the bazel workspace dependencies will be added.

USAGE
}

AIRGAPPED_DIR_CONTENTS="ALL"
FORCE_REBUILD=false

while getopts ':c:f' flag; do
  case "${flag}" in
    c) AIRGAPPED_DIR_CONTENTS="${OPTARG}";;
    f) FORCE_REBUILD=true;;
    \?) echo "Unexpected option: -${OPTARG}" >&2
        usage
        exit 1
        ;;
    :) echo "Option -${OPTARG} requires an argument" >&2
       usage
       exit 1
       ;;
    *) echo "Internal Error: Unhandled option: -${flag}" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

# We do not accept additional arguments.
if [[ "$#" -gt 0 ]]; then
  echo "Unexpected arguments:" "$@" >&2
  exit 1
fi

if [[ ${AIRGAPPED_DIR_CONTENTS} != "ALL" && \
      ${AIRGAPPED_DIR_CONTENTS} != "DISTDIR" && \
      ${AIRGAPPED_DIR_CONTENTS} != "CACHE" ]]; then
  echo "Invalid -c option: ${AIRGAPPED_DIR_CONTENTS}." >&2
  echo "Expected ALL, DISTDIR, or CACHE." >&2
  exit 1
fi


################################################################################
# Check if a previous airgapped directory has been built.
################################################################################
if [[ -d ${BAZEL_AIRGAPPED_DIR} ]]; then
  if [[ ${FORCE_REBUILD} = false ]]; then
    while true; do
      read -p "Airgapped directory exists, rebuild? [Y/n]" yn
      case $yn in
          "") rm -rf ${BAZEL_AIRGAPPED_DIR}; break;;
          [Yy]*) rm -rf ${BAZEL_AIRGAPPED_DIR}; break;;
          [Nn]*) exit;;
          *) echo "Please enter [Yy] or [Nn]."
      esac
    done
  else
    rm -rf ${BAZEL_AIRGAPPED_DIR}
  fi
fi

################################################################################
# Setup the airgapped directory.
################################################################################
mkdir -p ${BAZEL_AIRGAPPED_DIR}

################################################################################
# Prepare the distdir.
################################################################################
if [[ ${AIRGAPPED_DIR_CONTENTS} == "ALL" || \
      ${AIRGAPPED_DIR_CONTENTS} == "DISTDIR" ]]; then
  echo $LINE_SEP
  echo "Preparing bazel offline distdir ..."
  mkdir -p ${BAZEL_AIRGAPPED_DIR}/${BAZEL_DISTDIR}
  cd ${BAZEL_AIRGAPPED_DIR}
  curl --silent --location \
    https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-linux-x86_64 \
    --output bazel
  chmod +x bazel
  git clone -b "${BAZEL_VERSION}" --depth 1 https://github.com/bazelbuild/bazel bazel-repo
  cd bazel-repo
  echo "Cloned bazel repo @ \"${BAZEL_VERSION}\" (commit $(git rev-parse HEAD))"
  ../bazel build @additional_distfiles//:archives.tar
  tar xvf bazel-bin/external/additional_distfiles/archives.tar \
    -C "../${BAZEL_DISTDIR}" \
    --strip-components=3
  cd ..
  rm -rf bazel-repo
  echo "Done."
fi

################################################################################
# Prepare the cache.
################################################################################
if [[ ${AIRGAPPED_DIR_CONTENTS} == "ALL" || \
      ${AIRGAPPED_DIR_CONTENTS} == "CACHE" ]]; then
  echo $LINE_SEP
  echo "Preparing bazel offline cachedir ..."
  cd ${REPO_TOP}
  mkdir -p ${BAZEL_AIRGAPPED_DIR}/${BAZEL_CACHEDIR}
  # Make bazel forget everything it knows, then download everything.
  bazelisk clean --expunge
  bazelisk fetch \
    --repository_cache=${BAZEL_AIRGAPPED_DIR}/${BAZEL_CACHEDIR} \
    //... \
    @remote_java_tools//... \
    @remote_java_tools_linux//... \
    @bindgen_clang_linux//... \
    @rules_rust_bindgen__bindgen-0.65.1//... \
    @rules_rust_bindgen__bindgen-cli-0.65.1//... \
    @go_sdk//... \
    @cmake-3.22.2-linux-x86_64//... \
    @gnumake_src//... \
    @go_sdk//... \
    @gcc_mxe_mingw32_files//... \
    @gcc_mxe_mingw64_files//... \
    @ninja_1.10.2_linux//... \
    @ot_python_wheels//... \
    @python3_toolchains//... \
    @remotejdk11_linux//... \
    @rustfmt_nightly-2023-10-05__x86_64-unknown-linux-gnu_tools//... \
    @rust_analyzer_1.71.1_tools//... \
    @rust_linux_x86_64__x86_64-unknown-linux-gnu__nightly_tools//... \
    @rust_linux_x86_64__riscv32imc-unknown-none-elf__nightly_tools//...
  cp -R "$(bazelisk info output_base)"/external/${BAZEL_PYTHON_WHEEL_REPO} \
    ${BAZEL_AIRGAPPED_DIR}/
  echo "Done."
fi

################################################################################
# Print some usage instructions.
################################################################################
if [[ ${AIRGAPPED_DIR_CONTENTS} == "ALL" ]]; then
  echo $LINE_SEP
  echo "To perform an airgapped build, ship the contents of ${BAZEL_AIRGAPPED_DIR} to your airgapped environment and then:"
  echo ""
  echo "bazelisk build --distdir=${BAZEL_AIRGAPPED_DIR}/${BAZEL_DISTDIR} --repository_cache=${BAZEL_AIRGAPPED_DIR}/${BAZEL_CACHEDIR} <label>"
fi
