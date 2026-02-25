// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_ATE_ATE_PERSO_BLOB_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_ATE_PERSO_BLOB_H_
#include <stddef.h>
#include <stdint.h>

#include <string>
#ifdef __cplusplus
extern "C" {
#endif

// The following definitions are taken from the OpenTitan repository:
// https://github.com/lowRISC/opentitan/blob/earlgrey_1.0.0/sw/device/silicon_creator/manuf/base/perso_tlv_data.h
// TODO(#183): Switch to using the OpenTitan definitions.

// Object types
typedef enum perso_tlv_object_type {
  kPersoObjectTypeX509Tbs = 0,
  kPersoObjectTypeX509Cert = 1,
  kPersoObjectTypeDevSeed = 2,
  kPersoObjectTypeCwtCert = 3,
  kPersoObjectTypeWasTbsHmac = 4,
  kPersoObjectTypeDeviceId = 5,
  kPersoObjectTypeGenericSeed = 6,
  kPersoObjectTypePersoSha256Hash = 7,
  kPersoObjectTypeBlobVersion = 15,
} perso_tlv_object_type_t;

// Header types
typedef uint16_t perso_tlv_object_header_v0_t;
typedef uint32_t perso_tlv_object_header_v1_t;
typedef uint16_t perso_tlv_cert_header_v0_t;
typedef uint32_t perso_tlv_cert_header_v1_t;

// Legacy aliases (deprecated)
typedef perso_tlv_object_header_v0_t perso_tlv_object_header_t;
typedef perso_tlv_cert_header_v0_t perso_tlv_cert_header_t;

// Header field definitions
typedef enum perso_tlv_obj_header_fields {
  // V0 (Legacy) 16-bit Header: 4-bit Type, 12-bit Size
  kObjhV0SizeFieldShift = 0,
  kObjhV0SizeFieldWidth = 12,
  kObjhV0SizeFieldMask = (1 << kObjhV0SizeFieldWidth) - 1,
  kObjhV0TypeFieldShift = kObjhV0SizeFieldWidth,
  kObjhV0TypeFieldWidth =
      sizeof(perso_tlv_object_header_v0_t) * 8 - kObjhV0SizeFieldWidth,
  kObjhV0TypeFieldMask = (1 << kObjhV0TypeFieldWidth) - 1,

  // V1 32-bit Header: 8-bit Type, 24-bit Size
  kObjhV1SizeFieldShift = 0,
  kObjhV1SizeFieldWidth = 24,
  kObjhV1SizeFieldMask = (1 << kObjhV1SizeFieldWidth) - 1,
  kObjhV1TypeFieldShift = 24,
  kObjhV1TypeFieldWidth = 8,
  kObjhV1TypeFieldMask = (1 << kObjhV1TypeFieldWidth) - 1,

  // Legacy aliases
  kObjhSizeFieldShift = kObjhV0SizeFieldShift,
  kObjhSizeFieldWidth = kObjhV0SizeFieldWidth,
  kObjhSizeFieldMask = kObjhV0SizeFieldMask,
  kObjhTypeFieldShift = kObjhV0TypeFieldShift,
  kObjhTypeFieldWidth = kObjhV0TypeFieldWidth,
  kObjhTypeFieldMask = kObjhV0TypeFieldMask,
} perso_tlv_obj_header_fields_t;

typedef enum perso_tlv_cert_header_fields {
  // V0 (Legacy) 16-bit Cert Header: 4-bit Name Size, 12-bit Cert Size
  kCrthV0SizeFieldShift = 0,
  kCrthV0SizeFieldWidth = 12,
  kCrthV0SizeFieldMask = (1 << kCrthV0SizeFieldWidth) - 1,
  kCrthV0NameSizeFieldShift = kCrthV0SizeFieldWidth,
  kCrthV0NameSizeFieldWidth =
      sizeof(perso_tlv_cert_header_v0_t) * 8 - kCrthV0SizeFieldWidth,
  kCrthV0NameSizeFieldMask = (1 << kCrthV0NameSizeFieldWidth) - 1,

  // V1 32-bit Cert Header: 8-bit Name Size, 24-bit Cert Size
  kCrthV1SizeFieldShift = 0,
  kCrthV1SizeFieldWidth = 24,
  kCrthV1SizeFieldMask = (1 << kCrthV1SizeFieldWidth) - 1,
  kCrthV1NameSizeFieldShift = 24,
  kCrthV1NameSizeFieldWidth = 8,
  kCrthV1NameSizeFieldMask = (1 << kCrthV1NameSizeFieldWidth) - 1,

  // Legacy aliases
  kCrthSizeFieldShift = kCrthV0SizeFieldShift,
  kCrthSizeFieldMask = kCrthV0SizeFieldMask,
  kCrthNameSizeFieldShift = kCrthV0NameSizeFieldShift,
  kCrthNameSizeFieldMask = kCrthV0NameSizeFieldMask,
} perso_tlv_cert_header_fields_t;

// Helper macros for field manipulation
#define PERSO_TLV_SET_FIELD(type_name, field_name, full_value, field_value) \
  {                                                                         \
    uint16_t mask = k##type_name##field_name##FieldMask;                    \
    uint16_t shift = k##type_name##field_name##FieldShift;                  \
    uint16_t fieldv = (uint16_t)(field_value)&mask;                         \
    uint16_t fullv = __builtin_bswap16((uint16_t)(full_value));             \
    mask = (uint16_t)(mask << shift);                                       \
    (full_value) = __builtin_bswap16(                                       \
        (uint16_t)((fullv & ~mask) | (((uint16_t)fieldv) << shift)));       \
  }

#define PERSO_TLV_GET_FIELD(type_name, field_name, full_value, field_value) \
  {                                                                         \
    uint16_t mask = k##type_name##field_name##FieldMask;                    \
    uint16_t shift = k##type_name##field_name##FieldShift;                  \
    *(field_value) = (__builtin_bswap16(full_value) >> shift) & mask;       \
  }

#define PERSO_TLV_SET_FIELD_V1(type_name, field_name, full_value, field_value) \
  {                                                                            \
    uint32_t mask = k##type_name##field_name##FieldMask;                       \
    uint32_t shift = k##type_name##field_name##FieldShift;                     \
    uint32_t fieldv = (uint32_t)(field_value)&mask;                            \
    uint32_t fullv = __builtin_bswap32((uint32_t)(full_value));                \
    mask = (uint32_t)(mask << shift);                                          \
    (full_value) = __builtin_bswap32(                                          \
        (uint32_t)((fullv & ~mask) | (((uint32_t)fieldv) << shift)));          \
  }

#define PERSO_TLV_GET_FIELD_V1(type_name, field_name, full_value, field_value) \
  {                                                                            \
    uint32_t mask = k##type_name##field_name##FieldMask;                       \
    uint32_t shift = k##type_name##field_name##FieldShift;                     \
    *(field_value) = (__builtin_bswap32(full_value) >> shift) & mask;          \
  }

// Certificate object structure
typedef struct perso_tlv_cert_obj {
  const char* cert_body_p;
  size_t cert_body_size;
  char name[kCrthNameSizeFieldMask + 1];
} perso_tlv_cert_obj_t;

#ifdef __cplusplus
}
#endif
#endif  // OPENTITAN_PROVISIONING_SRC_ATE_ATE_PERSO_BLOB_H_
