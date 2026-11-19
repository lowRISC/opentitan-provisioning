// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include "src/ate/ate_perso_blob.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

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

    test_request_.key_label_size = test_response_.key_label_size;
    memcpy(test_request_.key_label, test_response_.key_label,
           test_request_.key_label_size);
    const uint8_t kEcdsaSha256TbsDer[] = {
        0x30, 0x14,                    // TBSCertificate ::= SEQUENCE (20 bytes)
        0xA0, 0x03, 0x02, 0x01, 0x02,  // [0] EXPLICIT Version (v3)
        0x02, 0x01, 0x01,              // serialNumber ::= INTEGER 1
        0x30, 0x0A,                    // signature ::= AlgorithmIdentifier
        0x06, 0x08,                    // OBJECT IDENTIFIER (8 bytes)
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,  // ecdsa-with-SHA256
    };
    test_request_.tbs_size = sizeof(kEcdsaSha256TbsDer);
    memset(test_request_.tbs, 0, sizeof(test_request_.tbs));
    memcpy(test_request_.tbs, kEcdsaSha256TbsDer, sizeof(kEcdsaSha256TbsDer));
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

TEST_F(AtePersoBlobTest, UnpackPersoBlobDetectsMldsaAndEcdsaOids) {
  device_id_bytes_t device_id;
  endorse_cert_signature_t signature;
  sha256_hash_t perso_fw_hash = {.raw = {0}};
  endorse_cert_request_t x509_tbs_certs[10];
  endorse_cert_response_t x509_certs[10];
  seed_t seeds[10];

  // 1. Default SetUp fixture uses ECDSA P-256 with SHA-256.
  {
    perso_blob_t test_blob;
    CreateTestPersoBlob(&test_blob);
    size_t tbs_cert_count = 10;
    size_t cert_count = 10;
    size_t seed_count = 10;
    EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature,
                              &perso_fw_hash, x509_tbs_certs, &tbs_cert_count,
                              x509_certs, &cert_count, seeds, &seed_count),
              0);
    EXPECT_EQ(tbs_cert_count, 1);
    EXPECT_EQ(x509_tbs_certs[0].algorithm_type, kSigningAlgorithmTypeEcdsa);
    EXPECT_EQ(x509_tbs_certs[0].hash_type, kHashTypeSha256);
    EXPECT_EQ(x509_tbs_certs[0].curve_type, kCurveTypeP256);
    EXPECT_EQ(x509_tbs_certs[0].signature_encoding, kSignatureEncodingDer);
  }

  // 2. ML-DSA-44 (2.16.840.1.101.3.4.3.17).
  {
    const uint8_t kMldsa44TbsDer[] = {
        0x30, 0x15,                    // TBSCertificate ::= SEQUENCE (21 bytes)
        0xA0, 0x03, 0x02, 0x01, 0x02,  // [0] EXPLICIT Version (v3)
        0x02, 0x01, 0x01,              // serialNumber ::= INTEGER 1
        0x30, 0x0B,                    // signature ::= AlgorithmIdentifier
        0x06, 0x09,                    // OBJECT IDENTIFIER (9 bytes)
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,  // ML-DSA-44
    };
    test_request_.tbs_size = sizeof(kMldsa44TbsDer);
    memset(test_request_.tbs, 0, sizeof(test_request_.tbs));
    memcpy(test_request_.tbs, kMldsa44TbsDer, sizeof(kMldsa44TbsDer));

    perso_blob_t test_blob;
    CreateTestPersoBlob(&test_blob);
    size_t tbs_cert_count = 10;
    size_t cert_count = 10;
    size_t seed_count = 10;
    EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature,
                              &perso_fw_hash, x509_tbs_certs, &tbs_cert_count,
                              x509_certs, &cert_count, seeds, &seed_count),
              0);
    EXPECT_EQ(tbs_cert_count, 1);
    EXPECT_EQ(x509_tbs_certs[0].algorithm_type, kSigningAlgorithmTypeMldsa);
    EXPECT_EQ(x509_tbs_certs[0].mldsa_param_set, kMldsaParamSet44);
  }

  // 3. ML-DSA-87 (2.16.840.1.101.3.4.3.19).
  {
    const uint8_t kMldsa87TbsDer[] = {
        0x30, 0x15,                    // TBSCertificate ::= SEQUENCE (21 bytes)
        0xA0, 0x03, 0x02, 0x01, 0x02,  // [0] EXPLICIT Version (v3)
        0x02, 0x01, 0x01,              // serialNumber ::= INTEGER 1
        0x30, 0x0B,                    // signature ::= AlgorithmIdentifier
        0x06, 0x09,                    // OBJECT IDENTIFIER (9 bytes)
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,  // ML-DSA-87
    };
    test_request_.tbs_size = sizeof(kMldsa87TbsDer);
    memset(test_request_.tbs, 0, sizeof(test_request_.tbs));
    memcpy(test_request_.tbs, kMldsa87TbsDer, sizeof(kMldsa87TbsDer));

    perso_blob_t test_blob;
    CreateTestPersoBlob(&test_blob);
    size_t tbs_cert_count = 10;
    size_t cert_count = 10;
    size_t seed_count = 10;
    EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature,
                              &perso_fw_hash, x509_tbs_certs, &tbs_cert_count,
                              x509_certs, &cert_count, seeds, &seed_count),
              0);
    EXPECT_EQ(tbs_cert_count, 1);
    EXPECT_EQ(x509_tbs_certs[0].algorithm_type, kSigningAlgorithmTypeMldsa);
    EXPECT_EQ(x509_tbs_certs[0].mldsa_param_set, kMldsaParamSet87);
  }

  // 4. Unsupported OID (e.g., ML-DSA-65 / non-supported algorithm) fails.
  {
    const uint8_t kUnsupportedTbsDer[] = {
        0x30, 0x15,                    // TBSCertificate ::= SEQUENCE (21 bytes)
        0xA0, 0x03, 0x02, 0x01, 0x02,  // [0] EXPLICIT Version (v3)
        0x02, 0x01, 0x01,              // serialNumber ::= INTEGER 1
        0x30, 0x0B,                    // signature ::= AlgorithmIdentifier
        0x06, 0x09,                    // OBJECT IDENTIFIER (9 bytes)
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,  // ML-DSA-65
    };
    test_request_.tbs_size = sizeof(kUnsupportedTbsDer);
    memset(test_request_.tbs, 0, sizeof(test_request_.tbs));
    memcpy(test_request_.tbs, kUnsupportedTbsDer, sizeof(kUnsupportedTbsDer));

    perso_blob_t test_blob;
    CreateTestPersoBlob(&test_blob);
    size_t tbs_cert_count = 10;
    size_t cert_count = 10;
    size_t seed_count = 10;
    EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature,
                              &perso_fw_hash, x509_tbs_certs, &tbs_cert_count,
                              x509_certs, &cert_count, seeds, &seed_count),
              -1);
  }
}

TEST_F(AtePersoBlobTest, UnpackPersoBlobRejectsMalformedObjectSizes) {
  struct TestCase {
    std::string name;
    std::vector<uint8_t> malformed_suffix;
  };

  const std::vector<TestCase> test_cases = {
      {
          "V0 DevSeed obj_size < header_size",
          // Type=2 (DevSeed), Size=1 (< 2)
          {0x20, 0x01},
      },
      {
          "V0 X509Cert obj_size < header_size",
          // Type=1 (X509Cert), Size=1 (< 2)
          {0x10, 0x01},
      },
      {
          "V1 DevSeed inner_size=0 (obj_size=4 < header_size=8)",
          {0xF0, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00},
      },
      {
          "V1 DevSeed inner_size=3 (obj_size=7 < header_size=8)",
          {0xF0, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03},
      },
      {
          "V1 X509Cert inner_size=3 (obj_size=7 < header_size=8)",
          {0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x03},
      },
      {
          "Truncated V1 prefix at end of blob",
          // 4-byte V1 version prefix without the following 4-byte V1 header
          {0xF0, 0x04, 0x00, 0x01},
      },
      {
          "V0 X509Cert truncated cert header",
          // Type=1 (X509Cert), Size=3 -> 1 byte left for 2-byte V0 cert header
          {0x10, 0x03, 0xAA},
      },
      {
          "V1 X509Cert truncated cert header",
          // V1 prefix + Type=1 (X509Cert), innerSize=7 -> 3 bytes left for
          // 4-byte V1 cert header
          {0xF0, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC},
      },
      {
          "V0 X509Cert cert_entry_size smaller than name_len + "
          "cert_header_size",
          // Type=1 (X509Cert), Size=6 (2B obj hdr + 2B cert hdr + 2B name),
          // cert header: NameSize=2, Size=3 (< 2 + 2 = 4)
          {0x10, 0x06, 0x20, 0x03, 'A', 'B'},
      },
  };

  for (const auto& tc : test_cases) {
    SCOPED_TRACE(tc.name);
    perso_blob_t test_blob;
    memset(&test_blob, 0, sizeof(test_blob));
    CreateTestPersoBlob(&test_blob);

    ASSERT_LE(test_blob.next_free + tc.malformed_suffix.size(),
              sizeof(test_blob.body));
    memcpy(test_blob.body + test_blob.next_free, tc.malformed_suffix.data(),
           tc.malformed_suffix.size());
    test_blob.next_free += tc.malformed_suffix.size();

    device_id_bytes_t device_id;
    endorse_cert_signature_t signature;
    sha256_hash_t perso_fw_hash = {.raw = {0}};
    size_t tbs_cert_count = 10;
    size_t cert_count = 10;
    size_t seed_count = 10;
    endorse_cert_request_t x509_tbs_certs[10];
    endorse_cert_response_t x509_certs[10];
    seed_t seeds[10];

    EXPECT_EQ(UnpackPersoBlob(&test_blob, &device_id, &signature,
                              &perso_fw_hash, x509_tbs_certs, &tbs_cert_count,
                              x509_certs, &cert_count, seeds, &seed_count),
              -1);
  }
}

}  // namespace
