// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_perso_blob.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "absl/log/log.h"
#include "src/ate/ate_api.h"

namespace {

int ExtractCertObject(const uint8_t* buf, size_t buf_size,
                      perso_tlv_cert_obj_t* cert_obj) {
  if (buf == nullptr || cert_obj == nullptr) {
    LOG(ERROR) << "Invalid input buffer or cert_obj pointer";
    return -1;
  }
  if (buf_size < sizeof(perso_tlv_object_header_t)) {
    LOG(ERROR) << "Buffer too small for object header";
    return -1;
  }

  const perso_tlv_object_header_t* objh =
      reinterpret_cast<const perso_tlv_object_header_t*>(buf);

  uint16_t obj_size;
  PERSO_TLV_GET_FIELD(Objh, Size, *objh, &obj_size);
  if (obj_size == 0 || obj_size > buf_size) {
    LOG(ERROR) << "Invalid object size: " << obj_size
               << ", buffer size: " << buf_size;
    return -1;
  }

  uint16_t obj_type;
  PERSO_TLV_GET_FIELD(Objh, Type, *objh, &obj_type);
  if (obj_type != kPersoObjectTypeX509Tbs) {
    LOG(ERROR) << "Invalid object type: " << obj_type << ", expected X509 TBS";
    return -1;
  }

  buf += sizeof(perso_tlv_object_header_t);
  buf_size -= sizeof(perso_tlv_object_header_t);

  const perso_tlv_cert_header_t* crth =
      reinterpret_cast<const perso_tlv_cert_header_t*>(buf);

  if (buf_size < sizeof(perso_tlv_cert_header_t)) {
    LOG(ERROR) << "Buffer too small for certificate header";
    return -1;
  }

  uint16_t name_len;
  PERSO_TLV_GET_FIELD(Crth, NameSize, *crth, &name_len);

  uint16_t cert_body_size;
  PERSO_TLV_GET_FIELD(Crth, Size, *crth, &cert_body_size);

  buf += sizeof(perso_tlv_cert_header_t);
  buf_size -= sizeof(perso_tlv_cert_header_t);

  if (buf_size < name_len) {
    LOG(ERROR) << "Buffer too small for certificate name: " << name_len
               << ", available: " << buf_size;
    return -1;
  }

  memcpy(cert_obj->name, buf, name_len);
  cert_obj->name[name_len] = '\0';

  buf += name_len;
  buf_size -= name_len;

  cert_body_size = cert_body_size - name_len - sizeof(perso_tlv_cert_header_t);
  if (cert_body_size > buf_size) {
    LOG(ERROR) << "Certificate body size exceeds available buffer size: "
               << cert_body_size << " > " << buf_size;
    return -1;
  }
  cert_obj->cert_body_size = cert_body_size;
  cert_obj->cert_body_p = reinterpret_cast<const char*>(buf);

  return 0;
}

// Helper function to extract device ID from a perso blob
int ExtractDeviceId(const uint8_t* buf, size_t buf_size,
                    device_id_bytes_t* device_id) {
  enum {
    kDeviceIdObjectSize =
        sizeof(device_id_bytes_t) + sizeof(perso_tlv_object_header_t)
  };

  if (buf_size < kDeviceIdObjectSize) {
    LOG(ERROR) << "Buffer too small for device ID object";
    return -1;
  }
  if (buf == nullptr || device_id == nullptr) {
    LOG(ERROR) << "Invalid input buffer or device ID pointer";
    return -1;
  }

  const perso_tlv_object_header_t* obj_hdr =
      reinterpret_cast<const perso_tlv_object_header_t*>(buf);
  uint16_t obj_size;
  uint16_t obj_type;

  PERSO_TLV_GET_FIELD(Objh, Size, *obj_hdr, &obj_size);
  PERSO_TLV_GET_FIELD(Objh, Type, *obj_hdr, &obj_type);

  if (obj_type == kPersoObjectTypeDeviceId) {
    if (obj_size !=
        sizeof(device_id_bytes_t) + sizeof(perso_tlv_object_header_t)) {
      LOG(ERROR) << "Invalid device ID object size: " << obj_size
                 << ", expected: "
                 << (sizeof(device_id_bytes_t) +
                     sizeof(perso_tlv_object_header_t));
      return -1;
    }
    memcpy(device_id->raw, buf + sizeof(perso_tlv_object_header_t),
           sizeof(device_id_bytes_t));
    return 0;
  }
  LOG(ERROR) << "Invalid object type for device ID: " << obj_type
             << ", expected: " << kPersoObjectTypeDeviceId;
  return -1;
}
}  // namespace

DLLEXPORT int UnpackPersoBlob(const perso_blob_t* blob,
                              device_id_bytes_t* device_id,
                              endorse_cert_signature_t* signature,
                              size_t* cert_count,
                              endorse_cert_request_t* request,
                              device_dev_seed_t* seeds, size_t* seed_count) {
  if (device_id == nullptr || signature == nullptr || cert_count == nullptr ||
      request == nullptr || seeds == nullptr || seed_count == nullptr) {
    LOG(ERROR) << "Invalid output parameters";
    return -1;
  }

  if (blob == nullptr || blob->body == nullptr || blob->next_free == 0) {
    LOG(ERROR) << "Invalid personalization blob";
    return -1;  // Invalid blob
  }

  memset(device_id->raw, 0, sizeof(device_id_bytes_t));
  memset(signature->raw, 0, sizeof(signature->raw));

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

  while (remaining >= sizeof(perso_tlv_object_header_t)) {
    const perso_tlv_object_header_t* obj_hdr =
        reinterpret_cast<const perso_tlv_object_header_t*>(buf);
    uint16_t obj_size;
    uint16_t obj_type;

    PERSO_TLV_GET_FIELD(Objh, Size, *obj_hdr, &obj_size);
    PERSO_TLV_GET_FIELD(Objh, Type, *obj_hdr, &obj_type);

    if (obj_size > remaining) {
      LOG(ERROR) << "Object size exceeds remaining buffer size: " << obj_size
                 << " > " << remaining;
      return -1;
    }

    switch (obj_type) {
      case kPersoObjectTypeDeviceId: {
        if (ExtractDeviceId(buf, obj_size, device_id) != 0) {
          LOG(ERROR) << "Failed to extract device ID";
          return -1;
        }
        break;
      }
      case kPersoObjectTypeX509Tbs: {
        if (*cert_count >= max_cert_count) {
          LOG(ERROR) << "Exceeded maximum number of TBS certificates: "
                     << *cert_count << " >= " << max_cert_count;
          return -1;
        }

        perso_tlv_cert_obj_t cert_obj;
        if (ExtractCertObject(buf, obj_size, &cert_obj) != 0) {
          LOG(ERROR) << "Failed to extract X509 TBS certificate object";
          return -1;
        }

        // Copy the certificate body.
        if (cert_obj.cert_body_size > kCertificateMaxSize) {
          LOG(ERROR) << "TBS certificate body size exceeds maximum: "
                     << cert_obj.cert_body_size << " > " << kCertificateMaxSize;
          return -1;
        }
        memset(request[*cert_count].tbs, 0, sizeof(request[*cert_count].tbs));
        memcpy(request[*cert_count].tbs, cert_obj.cert_body_p,
               cert_obj.cert_body_size);
        request[*cert_count].tbs_size = cert_obj.cert_body_size;

        // Copy the key label.
        size_t key_label_size = strlen(cert_obj.name);
        if (key_label_size > kCertificateKeyLabelMaxSize) {
          LOG(ERROR) << "Key label size exceeds maximum: " << key_label_size
                     << " > " << kCertificateKeyLabelMaxSize;
          return -1;
        }
        memset(request[*cert_count].key_label, 0,
               sizeof(request[*cert_count].key_label));
        memcpy(request[*cert_count].key_label, cert_obj.name, key_label_size);
        request[*cert_count].key_label_size = key_label_size;

        request[*cert_count].hash_type = kHashTypeSha256;
        request[*cert_count].curve_type = kCurveTypeP256;
        request[*cert_count].signature_encoding = kSignatureEncodingDer;
        (*cert_count)++;
        break;
      }

      case kPersoObjectTypeWasTbsHmac: {
        if (obj_size != sizeof(endorse_cert_signature_t) +
                            sizeof(perso_tlv_object_header_t)) {
          LOG(ERROR) << "Invalid size for WAS TBS HMAC object: " << obj_size
                     << ", expected: "
                     << (sizeof(endorse_cert_signature_t) +
                         sizeof(perso_tlv_object_header_t));
          return -1;
        }
        memcpy(signature->raw, buf + sizeof(perso_tlv_object_header_t),
               sizeof(signature->raw));
        break;
      }

      case kPersoObjectTypeDevSeed: {
        if (*seed_count >= max_seed_count) {
          LOG(ERROR) << "Exceeded maximum number of device seeds: "
                     << *seed_count << " >= " << max_seed_count;
          return -1;
        }
        if (obj_size >
            kDeviceDevSeedBytesSize + sizeof(perso_tlv_object_header_t)) {
          LOG(ERROR) << "Invalid device seed object size: " << obj_size
                     << ", expected: "
                     << (kDeviceDevSeedBytesSize +
                         sizeof(perso_tlv_object_header_t));
          return -1;
        }

        seeds[*seed_count].size = obj_size - sizeof(perso_tlv_object_header_t);
        memcpy(seeds[*seed_count].raw, buf + sizeof(perso_tlv_object_header_t),
               seeds[*seed_count].size);

        (*seed_count)++;
        break;
      }
    }

    buf += obj_size;
    remaining -= obj_size;
  }

  if (signature->raw[0] == 0) {
    LOG(ERROR) << "No WAS TBS HMAC found in the blob";
    return -1;
  }
  if (*cert_count == 0) {
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
                            perso_blob_t* blob) {
  if (blob == nullptr) {
    LOG(ERROR) << "Invalid personalization blob pointer";
    return -1;
  }
  if (cert_count == 0 || certs == nullptr) {
    LOG(ERROR) << "Invalid certificate count or certs pointer";
    return -1;
  }

  memset(blob, 0, sizeof(perso_blob_t));

  for (size_t i = 0; i < cert_count; i++) {
    const endorse_cert_response_t& cert = certs[i];
    if (cert.cert_size == 0) {
      LOG(ERROR) << "Invalid certificate at index " << i;
      return -1;
    }

    // Calculate the size of the object header and certificate header.
    size_t cert_entry_size =
        sizeof(perso_tlv_cert_header_t) + cert.key_label_size + cert.cert_size;
    size_t obj_size = sizeof(perso_tlv_object_header_t) + cert_entry_size;

    if (blob->next_free + obj_size > sizeof(blob->body)) {
      LOG(ERROR) << "Personalization blob is full, cannot add more objects";
      return -1;
    }

    // Set up the object header.
    uint8_t* buf = blob->body + blob->next_free;
    perso_tlv_object_header_t* obj_hdr =
        reinterpret_cast<perso_tlv_object_header_t*>(buf);
    PERSO_TLV_SET_FIELD(Objh, Size, *obj_hdr, obj_size);
    PERSO_TLV_SET_FIELD(Objh, Type, *obj_hdr, kPersoObjectTypeX509Cert);

    // Set up the certificate header.
    buf += sizeof(perso_tlv_object_header_t);
    perso_tlv_cert_header_t* cert_hdr =
        reinterpret_cast<perso_tlv_cert_header_t*>(buf);
    PERSO_TLV_SET_FIELD(Crth, Size, *cert_hdr, cert_entry_size);
    PERSO_TLV_SET_FIELD(Crth, NameSize, *cert_hdr, cert.key_label_size);

    // Copy the name and certificate data.
    buf += sizeof(perso_tlv_cert_header_t);
    memcpy(buf, cert.key_label, cert.key_label_size);

    // Copy the certificate data.
    buf += cert.key_label_size;
    memcpy(buf, cert.cert, cert.cert_size);

    // Update the next free offset in the blob.
    blob->next_free += obj_size;
    blob->num_objects++;
  }
  return 0;
}
