#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 --input_tar <input.tar.gz> --output_tar <output.tar.gz>"
  echo "  --hsm_module <pkcs.some>     Path to the PKCS#11 module."
  echo "  --token <token>              Token name."
  echo "  --softhsm_config <config>    Path to the SoftHSM config file. Optional."
  echo "  --hsm_pin <pin>              PIN for the token."
  echo "  --input_tar <input.tar.gz>   Path to the input tarball."
  echo "  --wipe                       Execute destroy commands before initializing the assets."
  echo "  --output_tar <output.tar.gz> Path to the output tarball. Optional."
  echo "  --help                       Show this help message."
  exit 1
}

readonly OUTDIR_HSM="hsm"
readonly OUTDIR_PUB="pub"

readonly INIT_HJSON=@@INIT_HJSON@@
readonly DESTROY_HJSON=@@DESTROY_HJSON@@
readonly HSMTOOL_BIN_DEFAULT=@@HSMTOOL_BIN@@

HSMTOOL_BIN="${HSMTOOL_BIN:-./${HSMTOOL_BIN_DEFAULT}}"

FLAGS_HSMTOOL_MODULE=""
FLAGS_HSMTOOL_TOKEN=""
FLAGS_SOFTHSM_CONFIG=""
FLAGS_HSMTOOL_PIN=""
FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""
FLAGS_WIPE=false
FLAGS_CA_CERTGEN_ONLY=false

LONGOPTS="hsm_module:,token:,softhsm_config:,hsm_pin:,input_tar:,output_tar:,wipe,help"
OPTS=$(getopt -o "" --long "${LONGOPTS}" -n "$0" -- "$@")

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

eval set -- "$OPTS"

while true; do
  case "$1" in
    --hsm_module)
      FLAGS_HSMTOOL_MODULE="$2"
      shift 2
      ;;
    --token)
      FLAGS_HSMTOOL_TOKEN="$2"
      shift 2
      ;;
    --softhsm_config)
      FLAGS_SOFTHSM_CONFIG="$2"
      shift 2
      ;;
    --hsm_pin)
      FLAGS_HSMTOOL_PIN="$2"
      shift 2
      ;;
    --input_tar)
      FLAGS_IN_TAR="$2"
      shift 2
      ;;
    --output_tar)
      FLAGS_OUT_TAR="$2"
      shift 2
      ;;
    --wipe)
      FLAGS_WIPE=true
      shift
      ;;
    --help)
      # Display usage information and exit.
      usage
      ;;
    --)
      shift
      break
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

if [[ -z "${FLAGS_HSMTOOL_MODULE}" ]]; then
  echo "Error: --hsm_module HSMTOOL_MODULE is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_TOKEN}" ]]; then
  echo "Error: --token HSMTOOL_TOKEN is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_PIN}" ]]; then
  echo "Error: --hsm_pin HSMTOOL_PIN is not set."
  exit 1
fi

if [[ ! -x "${HSMTOOL_BIN}" ]]; then
  echo "Error: HSMTOOL_BIN is not set or not executable."
  exit 1
fi

if [[ -n "${FLAGS_IN_TAR}" && "${FLAGS_IN_TAR}" != *.tar.gz  ]]; then
  echo "Error: Input tarball must have .tar.gz extension."
  exit 1
fi

if [[ -n "${FLAGS_OUT_TAR}" && "${FLAGS_OUT_TAR}" != *.tar.gz  ]]; then
  echo "Error: Output tarball must have .tar.gz extension."
  exit 1
fi

if [[ -n "${FLAGS_IN_TAR}" ]]; then
  if [[ ! -f "${FLAGS_IN_TAR}" ]]; then
    echo "Error: Input tarball does not exist."
    exit 1
  fi
  echo "Extracting input tarball ${FLAGS_IN_TAR}"
  tar -xzf "${FLAGS_IN_TAR}"
fi


# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_HSM}" "${OUTDIR_PUB}"

echo "softhsm-config: ${FLAGS_SOFTHSM_CONFIG}"
echo "hsmtool-module: ${FLAGS_HSMTOOL_MODULE}"
echo "hsmtool-token: ${FLAGS_HSMTOOL_TOKEN}"
echo "hsmtool-bin: ${HSMTOOL_BIN}"

hsmtool_vars=()
if [[ -n "${FLAGS_SOFTHSM_CONFIG}" ]]; then
  hsmtool_vars+=(SOFTHSM2_CONF="${FLAGS_SOFTHSM_CONFIG}")
fi
hsmtool_vars+=(
  HSMTOOL_MODULE="${FLAGS_HSMTOOL_MODULE}"
  HSMTOOL_USER="user"
  HSMTOOL_TOKEN="${FLAGS_HSMTOOL_TOKEN}"
  HSMTOOL_PIN="${FLAGS_HSMTOOL_PIN}"
)

hsmtool_args=(
  "${HSMTOOL_BIN}"
  --logging=info
)

if [[ "${FLAGS_WIPE}" == true ]]; then
  echo "Running hsmtool destroy (--wipe) operation."

  read -p "Are you sure you want to run the ${DESTROY_HJSON} script? (y/n) " -n 1 -r
  echo
  if [[ ! ${REPLY} =~ ^[Yy]$ ]]; then
    echo "Aborting destroy operation."
    exit 1
  fi

  env "${hsmtool_vars[@]}" "${hsmtool_args[@]}" exec "${DESTROY_HJSON}"
fi

echo "Running hsmtool"
env "${hsmtool_vars[@]}" "${hsmtool_args[@]}" exec "${INIT_HJSON}"

if [[ -n "${FLAGS_OUT_TAR}" ]]; then
  echo "Exporting HSM data to ${FLAGS_OUT_TAR}"
  tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_HSM}" "${OUTDIR_PUB}"
  rm -rf "${OUTDIR_HSM}"
fi
