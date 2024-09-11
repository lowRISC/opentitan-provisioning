// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OT_PROVISIONING_SRC_ATE_ATE_API_H
#define OT_PROVISIONING_SRC_ATE_ATE_API_H
#include <stddef.h>
#include <stdint.h>

#include <string>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef DLLEXPORT
#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else  // not _WIN32
#define DLLEXPORT
#endif  // _WIN32
#endif  // DLLEXPORT

#define SKU_SPECIFIC_SIZE 128

/**
 * blobType is tag indicating the blob content.
 */
enum BlobType : uint32_t {
  RSA_2048_KEY_PAYLOAD = 3,
  ECC_256_KEY_PAYLOAD = 4,
  ECC_384_KEY_PAYLOAD = 5,
  RSA_3072_KEY_PAYLOAD = 7,
  RSA_4096_KEY_PAYLOAD = 9,
  RSA_2048_KEY_CERT = RSA_2048_KEY_PAYLOAD * 2,  // 6
  ECC_256_KEY_CERT = ECC_256_KEY_PAYLOAD * 2,    // 8
  ECC_384_KEY_CERT = ECC_384_KEY_PAYLOAD * 2,    // 10
  RSA_3072_KEY_CERT = RSA_3072_KEY_PAYLOAD * 2,  // 14
  RSA_4096_KEY_CERT = RSA_4096_KEY_PAYLOAD * 2,  // 18
};

/**
 * DeviceLifeCycle encodes the state of the device as it is being manufactured
 * and provisioned for shipment.
 */
enum DeviceLifeCycle : uint32_t {
  DEVICE_LIFE_CYCLE_UNSPECIFIED = 0,  // default -- invalid in messages
  DEVICE_LIFE_CYCLE_RAW = 1,
  DEVICE_LIFE_CYCLE_TEST_LOCKED = 2,
  DEVICE_LIFE_CYCLE_TEST_UNLOCKED = 3,
  DEVICE_LIFE_CYCLE_DEV = 4,
  DEVICE_LIFE_CYCLE_PROD = 5,
  DEVICE_LIFE_CYCLE_PROD_END = 6,
  DEVICE_LIFE_CYCLE_RMA = 7,
  DEVICE_LIFE_CYCLE_SCRAP = 8,
  DEVICE_LIFE_CYCLE_INVALID = 9,
  DEVICE_LIFE_CYCLE_EOL = 10,
};

enum ProvState : uint32_t {
  DEVICE_STATE_UNSPECIFIED = 0,  // default -- not valid in message
  DEVICE_STATE_PROVISIONED = 1,  // device provisioned, and data is valid
  DEVICE_STATE_PROV_READ = 2,    // provisioned and read
  DEVICE_STATE_PROV_REPORT = 3,  // provisioned and reported to customer
  DEVICE_STATE_INVALID = 4,      // provision failed – data is invalid
  DEVICE_STATE_REVOKED = 5,      // manufacturer revoked the provisioning data
};

enum DeviceIdPubFormat : uint32_t {
  DEVICE_ID_PUB_FORMAT_UNSPECIFIED = 0,  // default -- not valid in messages
  DEVICE_ID_PUB_FORMAT_DER = 1,
  DEVICE_ID_PUB_FORMAT_PEM = 2,
  DEVICE_ID_PUB_FORMAT_RAW_ECDSA = 3,  // X & Y
};

/**
 * The blob_t is a blob of data passed from ATE to secigen.
 * keep fields 4-bytes aligned.
 */
typedef struct Blob {
  /** type of blob */
  BlobType type;
  /** length of the value field */
  uint32_t len;
  /** blob value - a place holder for the data*/
  uint8_t value[1];
} blob_t;

/**
 * ate_client_ptr is an opaque pointer to an AteClient instance.
 */
typedef struct {
} * ate_client_ptr;

typedef struct {
  // Endpoint address in IP or DNS format including port number. For example:
  // "localhost:5000".
  const char* target;

  // File containing the Client certificate in PEM format. Required when
  // `enable_mtls` set to true.
  const char* pem_cert_chain;

  // File containing the Client secret key in PEM format. Required when
  // `enable_mtls` set to true.
  const char* pem_private_key;

  // File containing the Server root certificates in PEM format. Required when
  // `enable_mtls` set to true.
  const char* pem_root_certs;

  // SKU authentication tokens. These tokens are considered secrets and are
  // used to perform authentication at the client gRPC call level.
  const char* sku_tokens;

  // Set to true to enable mTLS connection. When set to false, the connection
  // is established with insecure credentials.
  bool enable_mtls;
} client_options_t;

/**
 * The device_id_t is a struct of data passed from secigen to ATE.
 * keep fields 4-bytes aligned.
 */
#pragma pack(push, 1)
typedef struct HardwareOrigin {
  uint16_t silicon_creator_id;
  uint16_t product_id;
  uint64_t device_identification_number;
} hardware_origin_t;

typedef struct DeviceId {
  hardware_origin_t hardware_origin;
  uint8_t sku_specific[SKU_SPECIFIC_SIZE];
  uint32_t crc32;
} device_id_t;
#pragma pack(pop)
/**
 * Creates an AteClient instance.
 *
 * The client instance should be created once and reused many times over a
 * long running session.
 *
 * @param client A pointer (an `ate_client_ptr`) to the created client instance.
 * @param options The secure channel attributes.
 */
DLLEXPORT void CreateClient(ate_client_ptr* client, client_options_t* options);

/**
 * Destroys an AteClient instance.
 *
 * @param client A client instance.
 */
DLLEXPORT void DestroyClient(ate_client_ptr client);

/**
 * initialize session for specific sku.
 *
 * @param client A client instance.
 * @param sku The SKU of the product to initialize for.
 * @param sku_auth The SKU auth.
 * @return The result of the operation.
 */
DLLEXPORT int InitSession(ate_client_ptr client, const char* sku,
                          const char* sku_auth);

/**
 * close session for specific sku.
 *
 * @param client A client instance.
 * @return The result of the operation.
 */
DLLEXPORT int CloseSession(ate_client_ptr client);

/**
 * Creates blobs containing keys and their certificates.
 *
 * @param client A client instance.
 * @param sku The SKU of the product to create the key/certificate for.
 * @param data The opaque blobs.
 * @param max_data_size (input/output) The maximal/returned buffer size
 * @return The result of the operation (blobs of 'blob_t' type).
 */
DLLEXPORT int CreateKeyAndCertificate(ate_client_ptr client, const char* sku,
                                      void* data, size_t* max_data_size,
                                      const void* serial_number,
                                      const size_t serial_number_size);

/**
 * Registers an OpenTitan device record.
 *
 * TODO(#16): implement device registration function.
 */
// DLLEXPORT int RegisterDevice(...);

#ifdef __cplusplus
}
#endif
#endif  // OT_PROVISIONING_SRC_ATE_ATE_API_H
