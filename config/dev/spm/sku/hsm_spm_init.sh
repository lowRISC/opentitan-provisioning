#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

usage () {
  echo "Usage: $0 [-o <output.tar.gz>]"
  echo "  -o <output.tar.gz> Path to the output tarball."
  exit 1
}

FLAGS_OUT_TAR=""

while getopts 'o:' opt; do
  case "${opt}" in
    o)
      FLAGS_OUT_TAR="${OPTARG}"
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

if [[ "$#" -gt 0 ]]; then
  echo "Unexpected arguments:" "$@" >&2
  exit 1
fi

if [[ -z "${FLAGS_OUT_TAR}" ]]; then
  echo "Error: Output tarball not specified."
  exit 1
fi

if [[ "${FLAGS_OUT_TAR}" != *.tar.gz  ]]; then
  echo "Error: Output tarball must have .tar.gz extension."
  exit 1
fi

if [[ ! -x "${HSMTOOL_BIN}" ]]; then
  echo "Error: HSMTOOL_BIN is not set or not executable."
  exit 1
fi

readonly OUTDIR_PUB="pub"

mkdir -p "${OUTDIR_PUB}"

# The script must be executed from its local directory.
"${HSMTOOL_BIN}"                   \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
   exec "hsm_spm_init.hjson"

tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_PUB}"
