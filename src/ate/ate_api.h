// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_ATE_ATE_API_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_ATE_API_H_
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

enum {
  kSkuSpecificSize = 128,
  kSymmetricKeyMaxSize = 32,
};

/**
 * ate_client_ptr is an opaque pointer to an AteClient instance.
 */
typedef struct {
} * ate_client_ptr;

typedef struct {
  // Endpoint address in IP or DNS format including port number. For example:
  // "localhost:5000".
  const char* pa_socket;

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
  uint8_t sku_specific[kSkuSpecificSize];
  uint32_t crc32;
} device_id_t;
#pragma pack(pop)

/**
 * Symmetric key seed type. The seed is provisioned by the manufacturer.
 */
typedef enum symmetric_key_seed {
  /** Low security seed. This seed is rotated infrequently. */
  kSymmetricKeySeedSecurityLow = 1,
  /** High security seed. This seed is rotated frequently. */
  kSymmetricKeySeedSecurityHigh = 2,
} symmetric_key_seed_t;

/**
 * Symmetric key type.
 */
typedef enum symmetric_key_type {
  /** Raw plaintext key. */
  kSymmetricKeyTypeRaw = 1,
  /** cSHAKE128 with the "LC_CTRL" customization string. */
  kSymmetricKeyTypHashedLcToken = 2,
} symmetric_key_type_t;

/**
 * Symmetric key size.
 */
typedef enum symmmetric_key_size {
  /** 128bit key size. */
  kSymmetricKeySize128 = 16,
  /** 256bit key size. */
  kSymmetricKeySize256 = 32,
} symmetric_key_size_t;

/**
 * Derive symmetric key parameters.
 */
typedef struct derive_symmetric_key_params {
  /** Symmetric key seed. */
  symmetric_key_seed_t seed;
  /** Symmetric key type. */
  symmetric_key_type_t type;
  /** Symmetric key size. */
  symmetric_key_size_t size;
  /** Symmetric key diversifier to use in KDF operation. */
  uint8_t diversifier[32];
} derive_symmetric_key_params_t;

/**
 * Derive symmetric key request.
 */
typedef struct derive_symmetric_key_request {
  /** SKU identifier. */
  const char* sku;
  /**
   * Number of keys requested. Equivalent to the size of the `params` array.
   */
  size_t params_count;
  /** Derive symmetric key parameters. */
  derive_symmetric_key_params_t* params;
} derive_symmetric_key_request_t;

/**
 * Symmetric key.
 */
typedef struct symmetric_key {
  /** Key size in bytes. */
  size_t size;
  /** Key data. */
  uint8_t key[kSymmetricKeyMaxSize];
} symmetric_key_t;

/**
 * Derive symmetric key response.
 */
typedef struct derive_symmetric_key_response {
  /** Number of symmetric keys. */
  size_t symmetric_key_count;
  /** Symmetric keys. */
  symmetric_key_t* symmetric_keys;
} derive_symmetric_key_response_t;

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
 * Allocates a `derive_symmetric_key_request_t` structure.
 *
 * The allocated structure should be freed using
 * `FreeDeriveSymmetricKeyRequest`.
 *
 * @param key_count The number of keys to allocate space for.
 * @return The allocated structure. Returns NULL on failure.
 */
DLLEXPORT derive_symmetric_key_response_t* AllocateDeriveSymmetricKeyResponse(
    size_t key_count);

/**
 * Frees a `derive_symmetric_key_response_t` structure.
 *
 * @param response The structure to free.
 */
DLLEXPORT void FreeDeriveSymmetricKeyResponse(
    derive_symmetric_key_response_t* response);

/**
 * Derive symmetric keys.
 *
 * The function derives symmetric keys based on the request parameters.
 * Allocate a `derive_symmetric_key_response_t` structure to store the response
 * by calling `AllocateDeriveSymmetricKeyResponse`.
 *
 * @param client A client instance.
 * @param request The request parameters.
 * @param response The response parameters.
 * @return The result of the operation.
 */
DLLEXPORT int DeriveSymmetricKeys(ate_client_ptr client,
                                  const derive_symmetric_key_request_t* request,
                                  derive_symmetric_key_response_t* response);

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_PROVISIONING_SRC_ATE_ATE_API_H_
