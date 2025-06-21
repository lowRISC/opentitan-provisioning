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
} perso_tlv_object_type_t;

// Header types
typedef uint16_t perso_tlv_object_header_t;
typedef uint16_t perso_tlv_cert_header_t;

// Header field definitions
typedef enum perso_tlv_obj_header_fields {
  kObjhSizeFieldShift = 0,
  kObjhSizeFieldWidth = 12,
  kObjhSizeFieldMask = (1 << kObjhSizeFieldWidth) - 1,
  kObjhTypeFieldShift = kObjhSizeFieldWidth,
  kObjhTypeFieldWidth =
      sizeof(perso_tlv_object_header_t) * 8 - kObjhSizeFieldWidth,
  kObjhTypeFieldMask = (1 << kObjhTypeFieldWidth) - 1,
} perso_tlv_obj_header_fields_t;

typedef enum perso_tlv_cert_header_fields {
  kCrthSizeFieldShift = 0,
  kCrthSizeFieldWidth = 12,
  kCrthSizeFieldMask = (1 << kCrthSizeFieldWidth) - 1,
  kCrthNameSizeFieldShift = kCrthSizeFieldWidth,
  kCrthNameSizeFieldWidth =
      sizeof(perso_tlv_cert_header_t) * 8 - kCrthSizeFieldWidth,
  kCrthNameSizeFieldMask = (1 << kCrthNameSizeFieldWidth) - 1,
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
