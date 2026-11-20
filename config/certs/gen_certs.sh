#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
set -e

# See docs/spm.md for more details on how use the keys and certificates
# produced by this script.

readonly CONFIG_PATH=${OPENTITAN_VAR_DIR}/config/certs/out
readonly CONFIG_TEMPLATE_PATH=${OPENTITAN_VAR_DIR}/config/certs/templates
readonly CA_KEY=${CONFIG_PATH}/ca-key.pem
readonly CA_CERT=${CONFIG_PATH}/ca-cert.pem

mkdir -p ${CONFIG_PATH}

OPENSSL_BIN="${OPENTITAN_VAR_DIR}/bin/openssl"
if [[ ! -x "${OPENSSL_BIN}" ]]; then
  OPENSSL_BIN="openssl"
fi

if [[ "${OT_PROV_MIXED_TLS}" == "yes" ]]; then
  echo "Creating mixed (ML-DSA-87 + RSA-4096) CA keys and certificates"
  readonly MLDSA_CA_KEY=${CONFIG_PATH}/ca-mldsa-key.pem
  readonly MLDSA_CA_CERT=${CONFIG_PATH}/ca-mldsa-cert.pem
  readonly RSA_CA_KEY=${CONFIG_PATH}/ca-rsa-key.pem
  readonly RSA_CA_CERT=${CONFIG_PATH}/ca-rsa-cert.pem

  "${OPENSSL_BIN}" genpkey -algorithm mldsa87 \
      -provparam ml-dsa.output_formats=seed-only \
      -out ${MLDSA_CA_KEY}
  "${OPENSSL_BIN}" req -x509 -key ${MLDSA_CA_KEY} -days 365 \
      -out ${MLDSA_CA_CERT} \
      -config ${CONFIG_TEMPLATE_PATH}/ca.cnf \
      -subj "/C=US/L=Mountain View/CN=OpenTitan ML-DSA CA"

  "${OPENSSL_BIN}" req -x509 -newkey rsa:4096 -days 365 -nodes \
      -keyout ${RSA_CA_KEY} \
      -out ${RSA_CA_CERT} \
      -config ${CONFIG_TEMPLATE_PATH}/ca.cnf \
      -subj "/C=US/L=Mountain View/CN=OpenTitan RSA CA"

  cat ${MLDSA_CA_CERT} ${RSA_CA_CERT} > ${CA_CERT}
else
  echo "Creating ML-DSA-87 CA key and certificate"
  "${OPENSSL_BIN}" genpkey -algorithm mldsa87 \
      -provparam ml-dsa.output_formats=seed-only \
      -out ${CA_KEY}
  "${OPENSSL_BIN}" req -x509 -key ${CA_KEY} -days 365 \
      -out ${CA_CERT} \
      -config ${CONFIG_TEMPLATE_PATH}/ca.cnf
fi

readonly SERVICE_CERT_REQ=${CONFIG_PATH}/pa-req.pem

create_key_and_cert () {
  ENDPOINT_CERT_REQ=${CONFIG_PATH}/${1}-req.pem
  echo "Creating ${1} private key and certificate signing request"

  envsubst \
    < ${CONFIG_TEMPLATE_PATH}/endpoint_${1}.cnf.tmpl \
    > ${CONFIG_PATH}/endpoint_${1}.cnf

  if [[ "${OT_PROV_MIXED_TLS}" == "yes" ]]; then
    "${OPENSSL_BIN}" genpkey -algorithm mldsa87 \
        -provparam ml-dsa.output_formats=seed-only \
        -out ${CONFIG_PATH}/${1}-key.pem
    "${OPENSSL_BIN}" req -new \
        -key ${CONFIG_PATH}/${1}-key.pem \
        -out ${ENDPOINT_CERT_REQ} \
        -config ${CONFIG_PATH}/endpoint_${1}.cnf
    "${OPENSSL_BIN}" x509 -req \
      -in ${ENDPOINT_CERT_REQ} \
      -days 60 \
      -CA ${MLDSA_CA_CERT} \
      -CAkey ${MLDSA_CA_KEY} \
      -CAcreateserial \
      -out ${CONFIG_PATH}/${1}-cert.pem \
      -extensions req_ext \
      -extfile ${CONFIG_PATH}/endpoint_${1}.cnf
    rm ${ENDPOINT_CERT_REQ}

    "${OPENSSL_BIN}" req -newkey rsa:4096 -nodes \
        -keyout ${CONFIG_PATH}/${1}-rsa-key.pem \
        -out ${ENDPOINT_CERT_REQ} \
        -config ${CONFIG_PATH}/endpoint_${1}.cnf
    "${OPENSSL_BIN}" x509 -req \
      -in ${ENDPOINT_CERT_REQ} \
      -days 60 \
      -CA ${RSA_CA_CERT} \
      -CAkey ${RSA_CA_KEY} \
      -CAcreateserial \
      -out ${CONFIG_PATH}/${1}-rsa-cert.pem \
      -extensions req_ext \
      -extfile ${CONFIG_PATH}/endpoint_${1}.cnf
    rm ${ENDPOINT_CERT_REQ}
    return
  fi

  "${OPENSSL_BIN}" genpkey -algorithm mldsa87 \
      -provparam ml-dsa.output_formats=seed-only \
      -out ${CONFIG_PATH}/${1}-key.pem
  "${OPENSSL_BIN}" req -new \
      -key ${CONFIG_PATH}/${1}-key.pem \
      -out ${ENDPOINT_CERT_REQ} \
      -config ${CONFIG_PATH}/endpoint_${1}.cnf

  echo "Signing ${1} certificate with CA key."
  "${OPENSSL_BIN}" x509 -req \
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
