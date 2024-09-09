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
 * DeviceLifeCycle allow to manage the state of the device as it is being
 * manufactured and provisioned for shipment and also are used to encode the
 * device ownership state DeviceLifeCycle allow to manage the state of the
 * device as it is being manufactured and provisioned for shipment and also are
 * used to encode the device ownership state
 */
enum DeviceLifeCycle : uint32_t {
  DEVICE_LIFE_CYCLE_UNSPECIFIED = 0,  // default -- invalid in messages
  DEVICE_LIFE_CYCLE_RAW = 1,
  DEVICE_LIFE_CYCLE_TEST_LOCKED = 2,
  DEVICE_LIFE_CYCLE_TEST_UNLOCKED = 3,
  DEVICE_LIFE_CYCLE_DEV = 4,
  DEVICE_LIFE_CYCLE_PROD = 5,
  DEVICE_LIFE_CYCLE_PROD_END = 6,  // the state TPM is delivered
  DEVICE_LIFE_CYCLE_RMA = 7,
  DEVICE_LIFE_CYCLE_SCRAP = 8,
  DEVICE_LIFE_CYCLE_OWNERSHIP_UNLOCED = 9,
  DEVICE_LIFE_CYCLE_OWNERSHIP_LOCKED = 10,
  DEVICE_LIFE_CYCLE_INVALID = 11,
  DEVICE_LIFE_CYCLE_EOL = 12,
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
typedef struct DeviceType {
  uint16_t silicon_creator;
  uint32_t product_identifier;
} device_type_t;

typedef struct HardwareOrigin {
  device_type_t device_type;
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
 * Registers a BMC's device record.
 *
 * @param client A client instance.
 * @param device_id_number Identifies the specific device.
 * @param dme_pub_key The DME key.
 * @param dme_pub_key_size The DME key size.
 * @param data The data blob.
 * @param data_size (input) The data size
 * @return The result of the operation.
 */
DLLEXPORT int RegisterDeviceBMC(
    ate_client_ptr client, const device_id_t* device_id,
    const void* dme_pub_key, const size_t dme_pub_key_size,
    const DeviceLifeCycle life_cycle, const uint8_t year, const uint8_t week,
    const uint16_t lot_num, const uint8_t wafer_id, const uint8_t x,
    const uint8_t y, const void* data, const size_t data_size);

/**
 * Registers a TPM's device record.
 *
 * @param client A client instance.
 * @param device_id_number Identifies the specific device.
 * @param certs The certificaes blob.
 * @param certsSize The certificaes blob size.
 * @param pSN The serial number.
 * @param snSize (input) The serial number size
 * @param year The manufacture year number
 * @param week The manufacture week number
 * @param lot_num The lot number
 * @param wafer_id The wafer ID number
 * @param y The y location
 * @param x The x location
 * @return The result of the operation.
 */
DLLEXPORT int RegisterDeviceTPM(
    ate_client_ptr client, const device_id_t* deviceID, const void* certs,
    const size_t certsSize, const void* pSN, const size_t snSize,
    const DeviceLifeCycle life_cycle, const uint8_t year, const uint8_t week,
    const uint16_t lot_num, const uint8_t wafer_id, const uint8_t x,
    const uint8_t y, const char* FT_lot);
#ifdef __cplusplus
}
#endif
#endif  // OT_PROVISIONING_SRC_ATE_ATE_API_H
