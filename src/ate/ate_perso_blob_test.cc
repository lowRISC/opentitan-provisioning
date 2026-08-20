// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include "src/ate/ate_perso_blob.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "src/ate/ate_api.h"
#include "src/testing/test_helpers.h"

namespace {

using testing::EqualsProto;

class AtePersoBlobTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize test data
    test_device_id_ = {.raw = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    test_signature_ = {.raw = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                               0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    test_response_.key_label_size = 8;
    memcpy(test_response_.key_label, "testkey1", 8);

    test_response_.cert_size = 128;
    memset(test_response_.cert, 0, sizeof(test_response_.cert));
    memset(test_response_.cert, 0x33, test_response_.cert_size);

    test_request_.key_label_size = test_request_.key_label_size;
    memcpy(test_request_.key_label, test_response_.key_label,
           test_request_.key_label_size);
    test_request_.tbs_size = 128;
    memset(test_request_.tbs, 0, sizeof(test_request_.tbs));
    memset(test_request_.tbs, 0x44, test_request_.tbs_size);
  }

  // Helper function to create a valid perso blob for testing
  void CreateTestPersoBlob(perso_blob_t* blob) {
    uint8_t* buf = blob->body;
    size_t offset = 0;

    // Add device ID object
    *reinterpret_cast<uint32_t*>(buf) = kPersoTlvVersionPrefixV1;
    buf += kPersoTlvVersionHeaderSize;
    offset += kPersoTlvVersionHeaderSize;
    uint32_t obj_size =
        sizeof(test_device_id_.raw) + sizeof(perso_tlv_object_header_v1_t);
    uint32_t* obj_hdr = reinterpret_cast<uint32_t*>(buf);
    *obj_hdr = 0;
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Type, *obj_hdr, kPersoObjectTypeDeviceId);
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Size, *obj_hdr, obj_size);

    memcpy(buf + sizeof(perso_tlv_object_header_v1_t), &test_device_id_.raw,
           sizeof(test_device_id_.raw));

    offset += obj_size;
    buf += obj_size;

    // Add signature object
    *reinterpret_cast<uint32_t*>(buf) = kPersoTlvVersionPrefixV1;
    buf += kPersoTlvVersionHeaderSize;
    offset += kPersoTlvVersionHeaderSize;
    obj_size =
        sizeof(test_signature_.raw) + sizeof(perso_tlv_object_header_v1_t);
    obj_hdr = reinterpret_cast<uint32_t*>(buf);
    *obj_hdr = 0;
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Type, *obj_hdr, kPersoObjectTypeWasTbsHmac);
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Size, *obj_hdr, obj_size);

    memcpy(buf + sizeof(perso_tlv_object_header_v1_t), &test_signature_.raw,
           sizeof(test_signature_.raw));

    offset += obj_size;
    buf += obj_size;

    // Add TBS certificate object
    *reinterpret_cast<uint32_t*>(buf) = kPersoTlvVersionPrefixV1;
    buf += kPersoTlvVersionHeaderSize;
    offset += kPersoTlvVersionHeaderSize;
    size_t cert_entry_size = sizeof(uint32_t) + test_request_.key_label_size +
                             test_request_.tbs_size;
    obj_size = sizeof(perso_tlv_object_header_v1_t) + cert_entry_size;

    obj_hdr = reinterpret_cast<uint32_t*>(buf);
    *obj_hdr = 0;
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Type, *obj_hdr, kPersoObjectTypeX509Tbs);
    PERSO_TLV_SET_FIELD_V1(ObjhV1, Size, *obj_hdr, obj_size);

    uint32_t* cert_hdr =
        reinterpret_cast<uint32_t*>(buf + sizeof(perso_tlv_object_header_v1_t));
    *cert_hdr = 0;
    PERSO_TLV_SET_FIELD_V1(CrthV1, NameSize, *cert_hdr,
                           test_request_.key_label_size);
    PERSO_TLV_SET_FIELD_V1(CrthV1, Size, *cert_hdr, cert_entry_size);

    uint8_t* cert_data =
        buf + sizeof(perso_tlv_object_header_v1_t) + sizeof(uint32_t);
    memcpy(cert_data, test_request_.key_label, test_request_.key_label_size);

    cert_data += test_request_.key_label_size;
    memcpy(cert_data, test_request_.tbs, test_request_.tbs_size);

    offset += obj_size;
    blob->next_free = offset;
    blob->num_objects = 3;
  }

  device_id_bytes_t test_device_id_;
  endorse_cert_signature_t test_signature_;
  endorse_cert_response_t test_response_;
  endorse_cert_request_t test_request_;
};

TEST_F(AtePersoBlobTest, UnpackPersoBlobSuccess) {
  perso_blob_t test_blob;
  CreateTestPersoBlob(&test_blob);

  device_id_bytes_t device_id;
  endorse_cert_signature_t signature;
  sha256_hash_t perso_fw_hash = {.raw = {0}};
  size_t tbs_cert_count = 10;
  size_t cert_count = 10;
  endorse_cert_request_t x509_tbs_certs[10];
  endorse_cert_response_t x509_certs[10];
  seed_t seeds[10];
  size_t seed_count = 10;

  EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature, &perso_fw_hash,
                            x509_tbs_certs, &tbs_cert_count, x509_certs,
                            &cert_count, seeds, &seed_count),
            0);

  EXPECT_EQ(tbs_cert_count, 1);
  EXPECT_EQ(cert_count, 0);
  EXPECT_EQ(seed_count, 0);
  EXPECT_THAT(device_id.raw, testing::ElementsAreArray(test_device_id_.raw));
  EXPECT_THAT(signature.raw, testing::ElementsAreArray(test_signature_.raw));

  EXPECT_EQ(x509_tbs_certs[0].key_label_size, test_request_.key_label_size);
  EXPECT_EQ(x509_tbs_certs[0].tbs_size, test_request_.tbs_size);
  EXPECT_THAT(x509_tbs_certs[0].key_label,
              testing::ElementsAreArray(test_request_.key_label));
  EXPECT_THAT(x509_tbs_certs[0].tbs,
              testing::ElementsAreArray(test_request_.tbs));
}

TEST_F(AtePersoBlobTest, UnpackPersoBlobNullInputs) {
  perso_blob_t test_blob;
  CreateTestPersoBlob(&test_blob);

  device_id_bytes_t device_id;
  endorse_cert_signature_t signature;
  sha256_hash_t perso_fw_hash = {.raw = {0}};
  size_t tbs_cert_count = 10;
  size_t cert_count = 10;
  endorse_cert_request_t x509_tbs_certs[10];
  endorse_cert_response_t x509_certs[10];
  seed_t seeds[10];
  size_t seed_count = 10;

  // Test null blob
  EXPECT_EQ(UnpackPersoBlob(nullptr, &device_id, &signature, &perso_fw_hash,
                            x509_tbs_certs, &tbs_cert_count, x509_certs,
                            &cert_count, seeds, &seed_count),
            -1);

  // Test null output parameters
  EXPECT_EQ(UnpackPersoBlob(&test_blob, nullptr, &signature, &perso_fw_hash,
                            x509_tbs_certs, &tbs_cert_count, x509_certs,
                            &cert_count, seeds, &seed_count),
            -1);
  EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, nullptr, &perso_fw_hash,
                            x509_tbs_certs, &tbs_cert_count, x509_certs,
                            &cert_count, seeds, &seed_count),
            -1);
}

TEST_F(AtePersoBlobTest, PackPersoBlobV0Success) {
  perso_blob_t output_blob;
  EXPECT_EQ(PackPersoBlob(1, &test_response_, 0, nullptr, &output_blob), 0);

  // Small cert with 8-byte name is automatically packed as V0:
  // - V0 Object Header (16-bit) = 2 bytes
  // - V0 Cert Header (16-bit) = 2 bytes
  // - Name = 8 bytes
  // - Cert = 128 bytes
  // Total = 140 bytes
  size_t expected_size = sizeof(perso_tlv_object_header_v0_t) +
                         sizeof(perso_tlv_cert_header_v0_t) +
                         test_response_.key_label_size +
                         test_response_.cert_size;
  EXPECT_EQ(output_blob.next_free, expected_size);
  EXPECT_EQ(output_blob.num_objects, 1);
  EXPECT_NE(*reinterpret_cast<uint32_t*>(output_blob.body),
            kPersoTlvVersionPrefixV1);
}

TEST_F(AtePersoBlobTest, PackPersoBlobV1Success) {
  endorse_cert_response_t v1_cert;
  v1_cert.type = kCertTypeX509;
  v1_cert.key_label_size = 24;
  memcpy(v1_cert.key_label, "long_dice_cert_name_v1__", 24);
  v1_cert.cert_size = 128;
  memset(v1_cert.cert, 0x55, v1_cert.cert_size);

  perso_blob_t output_blob;
  EXPECT_EQ(PackPersoBlob(1, &v1_cert, 0, nullptr, &output_blob), 0);

  size_t expected_size = kPersoTlvVersionHeaderSize +
                         sizeof(perso_tlv_object_header_v1_t) +
                         sizeof(perso_tlv_cert_header_v1_t) +
                         v1_cert.key_label_size + v1_cert.cert_size;
  EXPECT_EQ(output_blob.next_free, expected_size);
  EXPECT_EQ(output_blob.num_objects, 1);
  EXPECT_EQ(*reinterpret_cast<uint32_t*>(output_blob.body),
            kPersoTlvVersionPrefixV1);
}

TEST_F(AtePersoBlobTest, PackRegistryPersoTlvDataMixedSuccess) {
  endorse_cert_response_t v1_cert;
  v1_cert.type = kCertTypeX509;
  v1_cert.key_label_size = 24;
  memcpy(v1_cert.key_label, "long_dice_cert_name_v1__", 24);
  v1_cert.cert_size = 128;
  memset(v1_cert.cert, 0x55, v1_cert.cert_size);

  seed_t test_seed;
  test_seed.type = kPersoObjectTypeGenericSeed;
  test_seed.size = 64;
  memset(test_seed.raw, 0x77, test_seed.size);

  perso_blob_t output_blob;
  EXPECT_EQ(PackRegistryPersoTlvData(&test_response_, 1, &v1_cert, 1,
                                     &test_seed, 1, &output_blob),
            0);
  EXPECT_EQ(output_blob.num_objects, 3);
}

TEST_F(AtePersoBlobTest, PackPersoBlobNullInputs) {
  perso_blob_t output_blob;

  // Test null blob
  EXPECT_EQ(PackPersoBlob(1, &test_response_, 0, nullptr, nullptr), -1);

  // Test null certs
  EXPECT_EQ(PackPersoBlob(1, nullptr, 0, nullptr, &output_blob), -1);

  // Test zero cert count
  EXPECT_EQ(PackPersoBlob(0, &test_response_, 0, nullptr, &output_blob), -1);
}

TEST_F(AtePersoBlobTest, PackPersoBlobOverflow) {
  perso_blob_t output_blob;

  // Create a certificate that would overflow the blob
  endorse_cert_response_t large_cert;
  large_cert.cert_size = sizeof(perso_blob_t);  // Too large
  large_cert.key_label_size = 8;
  memcpy(large_cert.key_label, "testkey1", 8);

  EXPECT_EQ(PackPersoBlob(1, &large_cert, 0, nullptr, &output_blob), -1);
}

}  // namespace
