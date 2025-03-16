#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
set -e

# See docs/spm.md for more details on how use the keys and certificates
# produced by this script.

readonly CONFIG_PATH=${OPENTITAN_VAR_DIR}/config/prod/certs/out
readonly CONFIG_TEMPLATE_PATH=${OPENTITAN_VAR_DIR}/config/prod/certs/templates
readonly CA_KEY=${CONFIG_PATH}/ca-key.pem
readonly CA_CERT=${CONFIG_PATH}/ca-cert.pem

mkdir -p ${CONFIG_PATH}

echo "Creating CA certificate"
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
    -keyout ${CA_KEY} \
    -out ${CA_CERT} \
    -config ${CONFIG_TEMPLATE_PATH}/ca.cnf

readonly SERVICE_CERT_REQ=${CONFIG_PATH}/pa-req.pem

create_key_and_cert () {
  ENDPOINT_CERT_REQ=${CONFIG_PATH}/${1}-req.pem
  echo "Creating ${1} private key and certificate signing request"

  envsubst \
    < ${CONFIG_TEMPLATE_PATH}/endpoint_${1}.cnf.tmpl \
    > ${CONFIG_PATH}/endpoint_${1}.cnf

  openssl req -newkey rsa:4096 -nodes \
      -keyout ${CONFIG_PATH}/${1}-key.pem \
      -out ${ENDPOINT_CERT_REQ} \
      -config ${CONFIG_PATH}/endpoint_${1}.cnf

  echo "Signing ${1} certificate with CA key."
  openssl x509 -req \
    -in ${ENDPOINT_CERT_REQ} \
    -days 60 \
    -CA ${CA_CERT} \
    -CAkey ${CA_KEY} \
    -CAcreateserial \
    -out ${CONFIG_PATH}/${1}-cert.pem \
    -extensions req_ext \
    -extfile ${CONFIG_PATH}/endpoint_${1}.cnf

  rm ${ENDPOINT_CERT_REQ}
}

create_key_and_cert "ate-client"
create_key_and_cert "pa-service"
create_key_and_cert "pb-service"
create_key_and_cert "spm-service"
