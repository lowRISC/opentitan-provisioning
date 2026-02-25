// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_perso_blob.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/ate/ate_api.h"

namespace {

// Helper to read the object header.
void ReadObjectHeader(const uint8_t* buf, size_t remaining, int blob_version,
                      uint32_t* obj_size, uint32_t* obj_type,
                      size_t* header_size) {
  if (blob_version == 1) {
    if (remaining < sizeof(perso_tlv_object_header_v1_t)) {
      *obj_size = 0;
      *obj_type = 0;
      *header_size = 0;
      return;
    }
    uint32_t hdr_val = *reinterpret_cast<const uint32_t*>(buf);
    PERSO_TLV_GET_FIELD_V1(ObjhV1, Size, hdr_val, obj_size);
    PERSO_TLV_GET_FIELD_V1(ObjhV1, Type, hdr_val, obj_type);
    *header_size = sizeof(perso_tlv_object_header_v1_t);
  } else {  // V0 Legacy
    if (remaining < sizeof(perso_tlv_object_header_v0_t)) {
      *obj_size = 0;
      *obj_type = 0;
      *header_size = 0;
      return;
    }
    uint16_t hdr_val = *reinterpret_cast<const uint16_t*>(buf);
    PERSO_TLV_GET_FIELD(ObjhV0, Size, hdr_val, obj_size);
    PERSO_TLV_GET_FIELD(ObjhV0, Type, hdr_val, obj_type);
    *header_size = sizeof(perso_tlv_object_header_v0_t);
  }
}

// Determines the blob format version.
absl::StatusOr<int> GetBlobVersion(const uint8_t* body, size_t size) {
  if (size < sizeof(perso_tlv_object_header_v0_t)) {
    return absl::InvalidArgumentError("Blob size too small to read header");
  }
  uint16_t hdr_val = *reinterpret_cast<const uint16_t*>(body);
  uint32_t type;
  PERSO_TLV_GET_FIELD(ObjhV0, Type, hdr_val, &type);
  if (type == kPersoObjectTypeBlobVersion) return 1;
  if (IsLegacyV0Blob(body, size)) return 0;
  return absl::InvalidArgumentError("Unknown or invalid blob version");
}

// Helper function to extract a certificate from a perso blob.
int ExtractCertObject(const uint8_t* buf, size_t buf_size, int blob_version,
                      perso_tlv_cert_obj_t* cert_obj) {
  if (buf == nullptr || cert_obj == nullptr) {
    LOG(ERROR) << "Invalid input buffer or cert_obj pointer";
    return -1;
  }

  uint32_t obj_size;
  uint32_t obj_type;
  size_t header_size;
  ReadObjectHeader(buf, buf_size, blob_version, &obj_size, &obj_type,
                   &header_size);

  if (obj_size == 0 || obj_size > buf_size) {
    LOG(ERROR) << "Invalid object size: " << obj_size
               << ", buffer size: " << buf_size;
    return -1;
  }
  if (obj_type != kPersoObjectTypeX509Tbs &&
      obj_type != kPersoObjectTypeX509Cert &&
      obj_type != kPersoObjectTypeCwtCert) {
    LOG(ERROR) << "Invalid object type: " << obj_type
               << ", expected X509 TBS or (full) cert";
    return -1;
  }

  buf += header_size;
  buf_size -= header_size;

  uint32_t name_len;
  uint32_t cert_entry_size;
  size_t cert_header_size;

  if (blob_version == 1) {
    if (buf_size < sizeof(perso_tlv_cert_header_v1_t)) return -1;
    uint32_t crth_val = *reinterpret_cast<const uint32_t*>(buf);
    PERSO_TLV_GET_FIELD_V1(CrthV1, Size, crth_val, &cert_entry_size);
    PERSO_TLV_GET_FIELD_V1(CrthV1, NameSize, crth_val, &name_len);
    cert_header_size = sizeof(perso_tlv_cert_header_v1_t);
  } else {
    if (buf_size < sizeof(perso_tlv_cert_header_v0_t)) return -1;
    uint16_t crth_val = *reinterpret_cast<const uint16_t*>(buf);
    PERSO_TLV_GET_FIELD(CrthV0, Size, crth_val, &cert_entry_size);
    PERSO_TLV_GET_FIELD(CrthV0, NameSize, crth_val, &name_len);
    cert_header_size = sizeof(perso_tlv_cert_header_v0_t);
  }

  buf += cert_header_size;
  buf_size -= cert_header_size;

  if (buf_size < name_len) {
    LOG(ERROR) << "Buffer too small for certificate name: " << name_len
               << ", available: " << buf_size;
    return -1;
  }

  memcpy(cert_obj->name, buf, name_len);
  cert_obj->name[name_len] = '\0';

  buf += name_len;
  buf_size -= name_len;

  uint32_t cert_body_size = cert_entry_size - name_len - cert_header_size;
  if (cert_body_size > buf_size) {
    LOG(ERROR) << "Certificate body size exceeds available buffer size: "
               << cert_body_size << " > " << buf_size;
    return -1;
  }

  cert_obj->cert_body_size = cert_body_size;
  cert_obj->cert_body_p = reinterpret_cast<const char*>(buf);

  return 0;
}

// Helper function to extract a TBS certificate from a perso blob.
int PackX509TbsCertStruct(const perso_tlv_cert_obj_t* cert_obj,
                          endorse_cert_request_t* tbs_cert) {
  if (cert_obj == nullptr || tbs_cert == nullptr) {
    LOG(ERROR) << "Invalid cert_obj or tbs_cert object pointer.";
    return -1;
  }

  // Copy the certificate body.
  if (cert_obj->cert_body_size > kCertificateMaxSize) {
    LOG(ERROR) << "TBS certificate body size exceeds maximum: "
               << cert_obj->cert_body_size << " > " << kCertificateMaxSize;
    return -1;
  }
  memset(tbs_cert->tbs, 0, sizeof(tbs_cert->tbs));
  memcpy(tbs_cert->tbs, cert_obj->cert_body_p, cert_obj->cert_body_size);
  tbs_cert->tbs_size = cert_obj->cert_body_size;

  // Copy the key label.
  size_t key_label_size = strlen(cert_obj->name);
  if (key_label_size > kCertificateKeyLabelMaxSize) {
    LOG(ERROR) << "Key label size exceeds maximum: " << key_label_size << " > "
               << kCertificateKeyLabelMaxSize;
    return -1;
  }
  memset(tbs_cert->key_label, 0, sizeof(tbs_cert->key_label));
  memcpy(tbs_cert->key_label, cert_obj->name, key_label_size);
  tbs_cert->key_label_size = key_label_size;

  tbs_cert->hash_type = kHashTypeSha256;
  tbs_cert->curve_type = kCurveTypeP256;
  tbs_cert->signature_encoding = kSignatureEncodingDer;

  return 0;
}

// Helper function to extract a (fully formed) certificate from a perso blob.
int PackCertStruct(const perso_tlv_cert_obj_t* cert_obj, uint16_t cert_type,
                   endorse_cert_response_t* cert) {
  if (cert_obj == nullptr || cert == nullptr) {
    LOG(ERROR) << "Invalid cert_obj or cert object pointer.";
    return -1;
  }
  if (cert_type != kPersoObjectTypeX509Cert &&
      cert_type != kPersoObjectTypeCwtCert) {
    LOG(ERROR) << "Invalid cert type.";
    return -1;
  }

  // Set the cert type.
  if (cert_type == kPersoObjectTypeCwtCert) {
    cert->type = kCertTypeCwt;
  } else {
    cert->type = kCertTypeX509;
  }

  // Copy the certificate body.
  if (cert_obj->cert_body_size > kCertificateMaxSize) {
    LOG(ERROR) << "Certificate body size exceeds maximum: "
               << cert_obj->cert_body_size << " > " << kCertificateMaxSize;
    return -1;
  }
  memset(cert->cert, 0, sizeof(cert->cert));
  memcpy(cert->cert, cert_obj->cert_body_p, cert_obj->cert_body_size);
  cert->cert_size = cert_obj->cert_body_size;

  // Copy the key label.
  size_t key_label_size = strlen(cert_obj->name);
  if (key_label_size > kCertificateKeyLabelMaxSize) {
    LOG(ERROR) << "Key label size exceeds maximum: " << key_label_size << " > "
               << kCertificateKeyLabelMaxSize;
    return -1;
  }
  memset(cert->key_label, 0, sizeof(cert->key_label));
  memcpy(cert->key_label, cert_obj->name, key_label_size);
  cert->key_label_size = key_label_size;

  return 0;
}

// Helper function to extract a device ID from a perso blob.
int ExtractDeviceId(const uint8_t* buf, size_t buf_size, int blob_version,
                    device_id_bytes_t* device_id) {
  if (buf == nullptr || device_id == nullptr) {
    LOG(ERROR) << "Invalid input buffer or device ID pointer";
    return -1;
  }

  uint32_t obj_size;
  uint32_t obj_type;
  size_t header_size;
  ReadObjectHeader(buf, buf_size, blob_version, &obj_size, &obj_type,
                   &header_size);

  if (buf_size < sizeof(device_id_bytes_t) + header_size) {
    LOG(ERROR) << "Buffer too small for device ID object";
    return -1;
  }

  if (obj_type == kPersoObjectTypeDeviceId) {
    if (obj_size != sizeof(device_id_bytes_t) + header_size) {
      LOG(ERROR) << "Invalid device ID object size: " << obj_size
                 << ", expected: " << (sizeof(device_id_bytes_t) + header_size);
      return -1;
    }
    memcpy(device_id->raw, buf + header_size, sizeof(device_id_bytes_t));
    return 0;
  }
  LOG(ERROR) << "Invalid object type for device ID: " << obj_type
             << ", expected: " << kPersoObjectTypeDeviceId;
  return -1;
}

// Helper function to pack a certificate object into a perso blob.
int PackCertTlvObject(const endorse_cert_response_t* cert, int blob_version,
                      perso_blob_t* blob) {
  // Calculate the size of the object header and certificate header.
  size_t cert_header_size = (blob_version == 1)
                                ? sizeof(perso_tlv_cert_header_v1_t)
                                : sizeof(perso_tlv_cert_header_v0_t);
  size_t cert_entry_size =
      cert_header_size + cert->key_label_size + cert->cert_size;

  uint16_t type = (cert->type == kCertTypeCwt) ? kPersoObjectTypeCwtCert
                                               : kPersoObjectTypeX509Cert;
  size_t header_size = (blob_version == 1)
                           ? sizeof(perso_tlv_object_header_v1_t)
                           : sizeof(perso_tlv_object_header_v0_t);
  size_t obj_size = header_size + cert_entry_size;

  if (blob->next_free + obj_size > sizeof(blob->body)) {
    LOG(ERROR) << "Personalization blob is full, cannot add more objects.";
    return -1;
  }

  // Set up the object header.
  uint8_t* buf = blob->body + blob->next_free;
  if (blob_version == 1) {
    uint32_t header = 0;
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Type, header, type);
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Size, header, obj_size);
    *reinterpret_cast<uint32_t*>(buf) = header;
  } else {
    uint16_t header = 0;
    PERSO_TLV_SET_FIELD(ObjhV0, Type, header, type);
    PERSO_TLV_SET_FIELD(ObjhV0, Size, header, obj_size);
    *reinterpret_cast<uint16_t*>(buf) = header;
  }

  // Set up the certificate header.
  buf += header_size;
  if (blob_version == 1) {
    uint32_t crth = 0;
    PERSO_TLV_SET_FIELD_V1(CrthV1, NameSize, crth, cert->key_label_size);
    PERSO_TLV_SET_FIELD_V1(CrthV1, Size, crth, cert_entry_size);
    *reinterpret_cast<uint32_t*>(buf) = crth;
  } else {
    uint16_t crth = 0;
    PERSO_TLV_SET_FIELD(CrthV0, NameSize, crth, cert->key_label_size);
    PERSO_TLV_SET_FIELD(CrthV0, Size, crth, cert_entry_size);
    *reinterpret_cast<uint16_t*>(buf) = crth;
  }

  // Copy the certificate name string.
  buf += cert_header_size;
  memcpy(buf, cert->key_label, cert->key_label_size);

  // Copy the certificate data.
  buf += cert->key_label_size;
  memcpy(buf, cert->cert, cert->cert_size);

  // Update the next free offset in the blob.
  blob->next_free += obj_size;
  blob->num_objects++;

  return 0;
}

// Helper function to pack a seed object into a perso blob.
int PackSeedTlvObject(const seed_t* seed, int blob_version,
                      perso_blob_t* blob) {
  size_t header_size = (blob_version == 1)
                           ? sizeof(perso_tlv_object_header_v1_t)
                           : sizeof(perso_tlv_object_header_v0_t);
  size_t obj_size = header_size + seed->size;
  if (blob->next_free + obj_size > sizeof(blob->body)) {
    LOG(ERROR) << "Personalization blob is full, cannot add more objects.";
    return -1;
  }

  // Set up the object header.
  uint8_t* buf = blob->body + blob->next_free;
  if (blob_version == 1) {
    uint32_t header = 0;
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Type, header, seed->type);
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Size, header, obj_size);
    *reinterpret_cast<uint32_t*>(buf) = header;
  } else {
    uint16_t header = 0;
    PERSO_TLV_SET_FIELD(ObjhV0, Type, header, seed->type);
    PERSO_TLV_SET_FIELD(ObjhV0, Size, header, obj_size);
    *reinterpret_cast<uint16_t*>(buf) = header;
  }

  // Copy the certificate data.
  buf += header_size;
  memcpy(buf, seed->raw, seed->size);

  // Update the next free offset in the blob.
  blob->next_free += obj_size;
  blob->num_objects++;

  return 0;
}

}  // namespace

// Checks if a blob was generated by a legacy V0 firmware by examining the
// first object.
DLLEXPORT bool IsLegacyV0Blob(const uint8_t* body, size_t size) {
  if (size < sizeof(perso_tlv_object_header_v0_t)) return false;
  uint16_t hdr_val = *reinterpret_cast<const uint16_t*>(body);
  uint32_t type;
  PERSO_TLV_GET_FIELD(ObjhV0, Type, hdr_val, &type);

  // If it's a V1 blob (starts with Type 15), it is NOT a legacy V0 blob.
  return type != kPersoObjectTypeBlobVersion;
}

DLLEXPORT int UnpackPersoBlob(
    const perso_blob_t* blob, device_id_bytes_t* device_id,
    endorse_cert_signature_t* signature, sha256_hash_t* perso_fw_hash,
    endorse_cert_request_t* tbs_certs, size_t* tbs_cert_count,
    endorse_cert_response_t* certs, size_t* cert_count, seed_t* seeds,
    size_t* seed_count) {
  if (device_id == nullptr || signature == nullptr ||
      perso_fw_hash == nullptr || tbs_certs == nullptr ||
      tbs_cert_count == nullptr || certs == nullptr || cert_count == nullptr ||
      seeds == nullptr || seed_count == nullptr) {
    LOG(ERROR) << "Invalid output parameters";
    return -1;
  }

  if (blob == nullptr || blob->next_free == 0) {
    LOG(ERROR) << "Invalid personalization blob";
    return -1;  // Invalid blob
  }

  memset(device_id->raw, 0, sizeof(device_id_bytes_t));
  memset(signature->raw, 0, sizeof(endorse_cert_signature_t));
  memset(perso_fw_hash->raw, 0, sizeof(sha256_hash_t));

  size_t max_tbs_cert_count = *tbs_cert_count;
  *tbs_cert_count = 0;
  size_t max_cert_count = *cert_count;
  *cert_count = 0;
  size_t max_seed_count = *seed_count;
  *seed_count = 0;

  const uint8_t* buf = blob->body;
  size_t remaining = blob->next_free;

  if (remaining > sizeof(blob->body)) {
    LOG(ERROR) << "Remaining buffer size exceeds maximum allowed: " << remaining
               << " > " << sizeof(blob->body);
    return -1;
  }

  absl::StatusOr<int> blob_version_or =
      GetBlobVersion(blob->body, blob->next_free);
  if (!blob_version_or.ok()) {
    LOG(ERROR) << blob_version_or.status().message();
    return -1;
  }
  int blob_version = *blob_version_or;

  if (blob_version == 1) {
    // Skip the Version Object (V1 header + 16-bit version).
    size_t version_obj_size =
        sizeof(perso_tlv_object_header_v0_t) + sizeof(uint16_t);
    buf += version_obj_size;
    remaining -= version_obj_size;
  }

  while (remaining >= sizeof(perso_tlv_object_header_v0_t)) {
    uint32_t obj_size;
    uint32_t obj_type;
    size_t header_size;

    ReadObjectHeader(buf, remaining, blob_version, &obj_size, &obj_type,
                     &header_size);

    if (obj_size == 0) {
      break;  // Padding
    }
    if (obj_size > remaining) {
      LOG(ERROR) << "Object size exceeds remaining buffer size: " << obj_size
                 << " > " << remaining;
      return -1;
    }

    switch (obj_type) {
      case kPersoObjectTypeDeviceId: {
        if (ExtractDeviceId(buf, obj_size, blob_version, device_id) != 0) {
          LOG(ERROR) << "Failed to extract device ID";
          return -1;
        }
        break;
      }

      case kPersoObjectTypeX509Tbs: {
        if (*tbs_cert_count >= max_tbs_cert_count) {
          LOG(ERROR) << "Exceeded maximum number of TBS certificates: "
                     << *tbs_cert_count << " >= " << max_tbs_cert_count;
          return -1;
        }
        perso_tlv_cert_obj_t cert_obj;
        if (ExtractCertObject(buf, obj_size, blob_version, &cert_obj) != 0) {
          LOG(ERROR) << "Failed to extract X509 TBS certificate object";
          return -1;
        }
        if (PackX509TbsCertStruct(&cert_obj, &tbs_certs[*tbs_cert_count]) !=
            0) {
          LOG(ERROR) << "Failed to pack TBS certificate endorsement request.";
          return -1;
        }
        (*tbs_cert_count)++;
        break;
      }

      case kPersoObjectTypeX509Cert:
      case kPersoObjectTypeCwtCert: {
        if (*cert_count >= max_cert_count) {
          LOG(ERROR) << "Exceeded maximum number of certificates: "
                     << *cert_count << " >= " << max_cert_count;
          return -1;
        }
        perso_tlv_cert_obj_t cert_obj;
        if (ExtractCertObject(buf, obj_size, blob_version, &cert_obj) != 0) {
          LOG(ERROR) << "Failed to extract X509 certificate object";
          return -1;
        }
        if (PackCertStruct(&cert_obj, obj_type, &certs[*cert_count]) != 0) {
          LOG(ERROR) << "Failed to pack TBS certificate endorsement request.";
          return -1;
        }
        (*cert_count)++;
        break;
      }

      case kPersoObjectTypeWasTbsHmac: {
        if (obj_size != sizeof(endorse_cert_signature_t) + header_size) {
          LOG(ERROR) << "Invalid size for WAS TBS HMAC object: " << obj_size
                     << ", expected: "
                     << (sizeof(endorse_cert_signature_t) + header_size);
          return -1;
        }
        memcpy(signature->raw, buf + header_size, sizeof(signature->raw));
        break;
      }

      case kPersoObjectTypeDevSeed:
      case kPersoObjectTypeGenericSeed: {
        if (*seed_count >= max_seed_count) {
          LOG(ERROR) << "Exceeded maximum number of seeds: " << *seed_count
                     << " >= " << max_seed_count;
          return -1;
        }
        // The size of a "dev_seed" is the maximum size a seed can be.
        if (obj_size > kDevSeedBytesSize + header_size) {
          LOG(ERROR) << "Invalid seed object size: " << obj_size
                     << ", expected size <=: "
                     << (kDevSeedBytesSize + header_size);
          return -1;
        }
        seeds[*seed_count].size = obj_size - header_size;
        seeds[*seed_count].type = (uint16_t)obj_type;
        memcpy(seeds[*seed_count].raw, buf + header_size,
               seeds[*seed_count].size);
        (*seed_count)++;
        break;
      }

      case kPersoObjectTypePersoSha256Hash: {
        if (obj_size != sizeof(sha256_hash_t) + header_size) {
          LOG(ERROR) << "Invalid size for perso firmware hash object: "
                     << obj_size
                     << ", expected: " << (sizeof(sha256_hash_t) + header_size);
          return -1;
        }
        memcpy(perso_fw_hash->raw, buf + header_size,
               sizeof(perso_fw_hash->raw));
        break;
      }
    }

    buf += obj_size;
    remaining -= obj_size;
  }

  bool all_zero = true;
  for (size_t i = 0; i < sizeof(signature->raw); ++i) {
    if (signature->raw[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    LOG(ERROR) << "No WAS TBS HMAC found in the blob";
    return -1;
  }

  if (*tbs_cert_count == 0) {
    LOG(ERROR) << "No TBS certificates found in the blob";
    return -1;
  }
  uint32_t device_id_sum = 0;
  for (size_t i = 0; i < sizeof(device_id_bytes_t); i++) {
    device_id_sum += device_id->raw[i];
  }
  if (device_id_sum == 0) {
    LOG(ERROR) << "Device ID is empty";
    return -1;
  }

  return 0;
}

DLLEXPORT int PackPersoBlob(size_t cert_count,
                            const endorse_cert_response_t* certs,
                            size_t ca_cert_count,
                            const endorse_cert_response_t* ca_certs,
                            bool is_legacy_v0, perso_blob_t* blob) {
  if (blob == nullptr) {
    LOG(ERROR) << "Invalid personalization blob pointer";
    return -1;
  }
  if (cert_count == 0 || certs == nullptr) {
    LOG(ERROR) << "Invalid certificate count or certs pointer";
    return -1;
  }

  memset(blob, 0, sizeof(perso_blob_t));

  int blob_version = is_legacy_v0 ? 0 : 1;

  // Add Version Object for V1
  if (blob_version == 1) {
    uint8_t* buf = blob->body;
    uint16_t header = 0;
    PERSO_TLV_SET_FIELD(ObjhV0, Type, header, kPersoObjectTypeBlobVersion);
    PERSO_TLV_SET_FIELD(
        ObjhV0, Size, header,
        (sizeof(perso_tlv_object_header_v0_t) + sizeof(uint16_t)));
    *reinterpret_cast<uint16_t*>(buf) = header;
    *reinterpret_cast<uint16_t*>(buf + sizeof(perso_tlv_object_header_v0_t)) =
        __builtin_bswap16(1);  // Version 1
    blob->next_free = sizeof(perso_tlv_object_header_v0_t) + sizeof(uint16_t);
    blob->num_objects = 1;
  }

  for (size_t i = 0; i < cert_count; i++) {
    const endorse_cert_response_t& cert = certs[i];
    if (cert.cert_size == 0) {
      LOG(ERROR) << "Invalid certificate at index " << i;
      return -1;
    }
    if (PackCertTlvObject(&cert, blob_version, blob) != 0) {
      LOG(ERROR) << "Unable to pack certificate into perso blob.";
      return -1;
    }
  }

  for (size_t i = 0; i < ca_cert_count; i++) {
    const endorse_cert_response_t& cert = ca_certs[i];
    if (cert.cert_size == 0) {
      LOG(ERROR) << "Invalid CA certificate at index " << i;
      return -1;
    }
    if (PackCertTlvObject(&cert, blob_version, blob) != 0) {
      LOG(ERROR) << "Unable to pack CA certificate into perso blob.";
      return -1;
    }
  }

  return 0;
}

DLLEXPORT int PackRegistryPersoTlvData(
    const endorse_cert_response_t* certs_endorsed_by_dut,
    size_t num_certs_endorsed_by_dut,
    const endorse_cert_response_t* certs_endorsed_by_spm,
    size_t num_certs_endorsed_by_spm, const seed_t* seeds, size_t num_seeds,
    bool is_legacy_v0, perso_blob_t* output) {
  if (certs_endorsed_by_dut == nullptr || certs_endorsed_by_spm == nullptr ||
      output == nullptr) {
    LOG(ERROR) << "Invalid certs or personalization blob pointer.";
    return -1;
  }
  if (num_certs_endorsed_by_dut == 0 && num_certs_endorsed_by_spm == 0 &&
      num_seeds == 0) {
    LOG(ERROR) << "No certs or seeds to send to registry.";
    return -1;
  }

  memset(output, 0, sizeof(perso_blob_t));

  int blob_version = is_legacy_v0 ? 0 : 1;

  // Add Version Object for V1
  if (blob_version == 1) {
    uint8_t* buf = output->body;
    uint16_t header = 0;
    PERSO_TLV_SET_FIELD(ObjhV0, Type, header, kPersoObjectTypeBlobVersion);
    PERSO_TLV_SET_FIELD(
        ObjhV0, Size, header,
        (sizeof(perso_tlv_object_header_v0_t) + sizeof(uint16_t)));
    *reinterpret_cast<uint16_t*>(buf) = header;
    *reinterpret_cast<uint16_t*>(buf + sizeof(perso_tlv_object_header_v0_t)) =
        __builtin_bswap16(1);  // Version 1
    output->next_free = sizeof(perso_tlv_object_header_v0_t) + sizeof(uint16_t);
    output->num_objects = 1;
  }

  // Pack all cert objects.
  const endorse_cert_response_t* all_certs[] = {certs_endorsed_by_dut,
                                                certs_endorsed_by_spm};
  size_t num_certs[] = {num_certs_endorsed_by_dut, num_certs_endorsed_by_spm};
  for (size_t i = 0; i < (sizeof(all_certs) / sizeof(all_certs[0])); i++) {
    for (size_t j = 0; j < num_certs[i]; j++) {
      const endorse_cert_response_t& cert = all_certs[i][j];
      if (cert.cert_size == 0) {
        LOG(ERROR) << "Invalid certificate at indices i:" << i << ", j:" << j;
        return -1;
      }
      if (PackCertTlvObject(&cert, blob_version, output) != 0) {
        LOG(ERROR) << "Unable to pack certificate into perso blob.";
        return -1;
      }
    }
  }

  // Pack all seed objects.
  for (size_t i = 0; i < num_seeds; i++) {
    const seed_t& seed = seeds[i];
    if (seed.size == 0) {
      LOG(ERROR) << "Invalid seed at index " << i;
      return -1;
    }
    if (PackSeedTlvObject(&seed, blob_version, output) != 0) {
      LOG(ERROR) << "Unable to pack seed into perso blob.";
      return -1;
    }
  }

  return 0;
}
