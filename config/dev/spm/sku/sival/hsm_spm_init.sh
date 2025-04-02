#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 -i <input.tar.gz> -o <output.tar.gz>"
  echo "  -i <input.tar.gz>  Path to the input tarball."
  echo "  -o <output.tar.gz> Path to the output tarball."
  exit 1
}
readonly OUTDIR_HSM="hsm"
readonly OUTDIR_CA="ca"
readonly OUTDIR_PUB="pub"

FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""

while getopts 'i:o:' opt; do
  case "${opt}" in
    i)
      FLAGS_IN_TAR="${OPTARG}"
      ;;
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

if [[ ! -x "${HSMTOOL_BIN}" ]]; then
  echo "Error: HSMTOOL_BIN is not set or not executable."
  exit 1
fi

if [[ -z "${FLAGS_IN_TAR}" ]]; then
  echo "Error: Input tarball not specified."
  exit 1
fi
if [[ "${FLAGS_IN_TAR}" != *.tar.gz  ]]; then
  echo "Error: Input tarball must have .tar.gz extension."
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

tar -xvf "${FLAGS_IN_TAR}"

"${HSMTOOL_BIN}"                   \
  --logging=info                   \
  --token="${SPM_HSM_TOKEN_SPM}"   \
  exec "02.hsm_spm.hjson"

# Remove the intermediate HSM folder.
rm -rf "${OUTDIR_HSM}" "${INPUT_TAR}"

# Generate tarball to deploy with the SPM.
tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_CA}" "${OUTDIR_PUB}"
