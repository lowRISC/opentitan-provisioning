// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_client.h"

#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <gtest/gtest.h>
#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/pa/proto/pa_mock.grpc.pb.h"
#include "src/testing/test_helpers.h"

namespace provisioning {
namespace ate {
namespace {

using pa::DeriveTokensRequest;
using pa::DeriveTokensResponse;
using pa::EndorseCertsRequest;
using pa::EndorseCertsResponse;
using pa::MockProvisioningApplianceServiceStub;
using testing::_;
using testing::DoAll;
using testing::EqualsProto;
using testing::IsTrue;
using testing::ParseTextProto;
using testing::Return;
using testing::SetArgPointee;

class AteTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create the Mock Provisioning Applicance Service.
    auto stub = absl::make_unique<MockProvisioningApplianceServiceStub>();
    // Keep a raw pointer to the mock around for setting up expectations.
    pa_service_ = stub.get();
    // Create an AteClient and give it ownership of the mock stub.
    ate_ = absl::make_unique<AteClient>(std::move(stub));
  }

  MockProvisioningApplianceServiceStub* pa_service_;
  std::unique_ptr<AteClient> ate_;
};

TEST_F(AteTest, EndorseCerts) {
  // Response that will be sent back for EndorseCerts.
  auto response = ParseTextProto<EndorseCertsResponse>(R"pb(
    certs: {
      key_label: "fake-key-label"
      cert: { blob: "fake-cert-blob" }
    })pb");

  // Expect EndorseCerts to be called.
  // The 2nd arg is expected to be a protobuf with the `sku` field.
  // We'll return the `response` struct and a status of `OK`.
  EXPECT_CALL(*pa_service_, EndorseCerts(_, EqualsProto(R"pb(
                                           sku: "abc123"
                                         )pb"),
                                         _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(grpc::Status::OK)));

  EndorseCertsRequest request;
  request.set_sku("abc123");

  // Call the AteClient and verify it returns OK with the expected response.
  EndorseCertsResponse result;
  EXPECT_THAT(ate_->EndorseCerts(request, &result).ok(), IsTrue());
  EXPECT_THAT(result, EqualsProto(response));
}

TEST_F(AteTest, DeriveTokens) {
  // Response that will be sent back for DeriveTokens.
  auto response = ParseTextProto<DeriveTokensResponse>(
      R"pb(
        tokens: { token: "foobar" }
      )pb");

  // Expect DeriveTokens to be called.
  // The 2nd arg is expected to be a protobuf with the `sku` field.
  // We'll return the `response` struct and a status of `OK`.
  EXPECT_CALL(*pa_service_, DeriveTokens(_, EqualsProto(R"pb(
                                           sku: "abc123"
                                         )pb"),
                                         _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(grpc::Status::OK)));

  DeriveTokensRequest request;
  request.set_sku("abc123");

  // Call the AteClient and verify it returns OK with the expected response.
  pa::DeriveTokensResponse result;
  EXPECT_THAT(ate_->DeriveTokens(request, &result).ok(), IsTrue());
  EXPECT_THAT(result, EqualsProto(response));
}

bssl::UniquePtr<EVP_PKEY> GenerateMldsaKey(int nid) {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(nid, nullptr));
  if (!ctx || !EVP_PKEY_keygen_init(ctx.get())) {
    return nullptr;
  }
  EVP_PKEY* raw_pkey = nullptr;
  if (!EVP_PKEY_keygen(ctx.get(), &raw_pkey)) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(raw_pkey);
}

bssl::UniquePtr<EVP_PKEY> GenerateRsaKey(int bits = 2048) {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!ctx || !EVP_PKEY_keygen_init(ctx.get()) ||
      !EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits)) {
    return nullptr;
  }
  EVP_PKEY* raw_pkey = nullptr;
  if (!EVP_PKEY_keygen(ctx.get(), &raw_pkey)) {
    return nullptr;
  }
  return bssl::UniquePtr<EVP_PKEY>(raw_pkey);
}

std::string KeyToPem(EVP_PKEY* pkey) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr,
                                nullptr)) {
    return "";
  }
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  return std::string(mem->data, mem->length);
}

bssl::UniquePtr<X509> GenerateCert(EVP_PKEY* subject_key, EVP_PKEY* signing_key,
                                   const std::string& subject_cn,
                                   const std::string& issuer_cn, bool is_ca,
                                   const EVP_MD* md = nullptr) {
  bssl::UniquePtr<X509> cert(X509_new());
  if (!cert) return nullptr;

  if (!X509_set_version(cert.get(), X509_VERSION_3)) return nullptr;
  bssl::UniquePtr<ASN1_INTEGER> serial(ASN1_INTEGER_new());
  if (!serial || !ASN1_INTEGER_set_uint64(serial.get(), 42) ||
      !X509_set_serialNumber(cert.get(), serial.get())) {
    return nullptr;
  }

  X509_NAME* s_name = X509_get_subject_name(cert.get());
  if (!X509_NAME_add_entry_by_txt(
          s_name, "CN", MBSTRING_UTF8,
          reinterpret_cast<const unsigned char*>(subject_cn.data()),
          subject_cn.size(), -1, 0)) {
    return nullptr;
  }

  X509_NAME* i_name = X509_get_issuer_name(cert.get());
  if (!X509_NAME_add_entry_by_txt(
          i_name, "CN", MBSTRING_UTF8,
          reinterpret_cast<const unsigned char*>(issuer_cn.data()),
          issuer_cn.size(), -1, 0)) {
    return nullptr;
  }

  if (!X509_set_pubkey(cert.get(), subject_key)) return nullptr;
  time_t now = time(nullptr);
  if (!ASN1_TIME_adj(X509_getm_notBefore(cert.get()), now, -1, 0)) {
    return nullptr;
  }
  if (!ASN1_TIME_adj(X509_getm_notAfter(cert.get()), now, 1, 0)) {
    return nullptr;
  }

  bssl::UniquePtr<BASIC_CONSTRAINTS> bc(BASIC_CONSTRAINTS_new());
  if (!bc) return nullptr;
  bc->ca = is_ca ? ASN1_BOOLEAN_TRUE : ASN1_BOOLEAN_FALSE;
  if (!X509_add1_ext_i2d(cert.get(), NID_basic_constraints, bc.get(),
                         /*crit=*/1, /*flags=*/0)) {
    return nullptr;
  }

  // Add SubjectKeyIdentifier (SHA-1 of public key) so leaf certs with matching
  // CN aren't treated as self-signed by X509_verify_cert.
  unsigned char* spki_der = nullptr;
  int spki_len = i2d_PUBKEY(subject_key, &spki_der);
  if (spki_len > 0) {
    unsigned char ski_hash[SHA_DIGEST_LENGTH];
    SHA1(spki_der, spki_len, ski_hash);
    OPENSSL_free(spki_der);
    bssl::UniquePtr<ASN1_OCTET_STRING> ski(ASN1_OCTET_STRING_new());
    ASN1_OCTET_STRING_set(ski.get(), ski_hash, SHA_DIGEST_LENGTH);
    X509_add1_ext_i2d(cert.get(), NID_subject_key_identifier, ski.get(),
                      /*crit=*/0, /*flags=*/0);
  }

  if (!is_ca) {
    // Add AuthorityKeyIdentifier matching signing_key
    unsigned char* ca_spki_der = nullptr;
    int ca_spki_len = i2d_PUBKEY(signing_key, &ca_spki_der);
    if (ca_spki_len > 0) {
      unsigned char aki_hash[SHA_DIGEST_LENGTH];
      SHA1(ca_spki_der, ca_spki_len, aki_hash);
      OPENSSL_free(ca_spki_der);
      bssl::UniquePtr<AUTHORITY_KEYID> akid(AUTHORITY_KEYID_new());
      akid->keyid = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(akid->keyid, aki_hash, SHA_DIGEST_LENGTH);
      X509_add1_ext_i2d(cert.get(), NID_authority_key_identifier, akid.get(),
                        /*crit=*/0, /*flags=*/0);
    }

    // Add SAN: DNS:localhost, IP:127.0.0.1
    bssl::UniquePtr<GENERAL_NAMES> gens(GENERAL_NAMES_new());
    bssl::UniquePtr<GENERAL_NAME> gen_dns(GENERAL_NAME_new());
    bssl::UniquePtr<ASN1_IA5STRING> ia5(ASN1_IA5STRING_new());
    ASN1_STRING_set(ia5.get(), "localhost", 9);
    GENERAL_NAME_set0_value(gen_dns.get(), GEN_DNS, ia5.release());
    sk_GENERAL_NAME_push(gens.get(), gen_dns.release());

    bssl::UniquePtr<GENERAL_NAME> gen_ip(GENERAL_NAME_new());
    bssl::UniquePtr<ASN1_OCTET_STRING> ip_oct(ASN1_OCTET_STRING_new());
    unsigned char loopback_ip[4] = {127, 0, 0, 1};
    ASN1_OCTET_STRING_set(ip_oct.get(), loopback_ip, 4);
    GENERAL_NAME_set0_value(gen_ip.get(), GEN_IPADD, ip_oct.release());
    sk_GENERAL_NAME_push(gens.get(), gen_ip.release());

    X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, gens.get(),
                      /*crit=*/0, /*flags=*/0);
  }

  if (!X509_sign(cert.get(), signing_key, md)) {
    return nullptr;
  }
  return cert;
}

std::string CertToPem(X509* cert) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(bio.get(), cert)) {
    return "";
  }
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  return std::string(mem->data, mem->length);
}

TEST(MldsaTlsTest, ValidateMldsaPrivateKey) {
  auto key44 = GenerateMldsaKey(EVP_PKEY_ML_DSA_44);
  ASSERT_TRUE(key44);
  auto key65 = GenerateMldsaKey(EVP_PKEY_ML_DSA_65);
  ASSERT_TRUE(key65);
  auto key87 = GenerateMldsaKey(EVP_PKEY_ML_DSA_87);
  ASSERT_TRUE(key87);
  auto rsa_key = GenerateRsaKey(2048);
  ASSERT_TRUE(rsa_key);

  EXPECT_TRUE(ValidateMldsaPrivateKey(KeyToPem(key44.get())).ok());
  EXPECT_TRUE(ValidateMldsaPrivateKey(KeyToPem(key65.get())).ok());
  EXPECT_TRUE(ValidateMldsaPrivateKey(KeyToPem(key87.get())).ok());

  auto rsa_status = ValidateMldsaPrivateKey(KeyToPem(rsa_key.get()));
  EXPECT_FALSE(rsa_status.ok());
  EXPECT_EQ(rsa_status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);

  // Verify interoperability with Go crypto/x509 seed-only PKCS#8 ML-DSA-87 key
  const char* go_mldsa87_key =
      "-----BEGIN PRIVATE KEY-----\n"
      "MDQCAQAwCwYJYIZIAWUDBAMTBCKAIN77tQZgHfe8jyxK4THV0vqNe8wXavL9nk8G\n"
      "Kpzk18+u\n"
      "-----END PRIVATE KEY-----\n";
  EXPECT_TRUE(ValidateMldsaPrivateKey(go_mldsa87_key).ok());

  EXPECT_FALSE(ValidateMldsaPrivateKey("").ok());
  EXPECT_FALSE(ValidateMldsaPrivateKey("invalid pem").ok());
}

TEST(MldsaTlsTest, VerifyMldsaCertificates) {
  auto ca_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_65);
  ASSERT_TRUE(ca_key);
  auto ca_cert = GenerateCert(ca_key.get(), ca_key.get(), "CA", "CA", true);
  ASSERT_TRUE(ca_cert);

  auto leaf44_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_44);
  auto leaf44_cert =
      GenerateCert(leaf44_key.get(), ca_key.get(), "leaf44", "CA", false);
  ASSERT_TRUE(leaf44_cert);

  auto leaf65_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_65);
  auto leaf65_cert =
      GenerateCert(leaf65_key.get(), ca_key.get(), "leaf65", "CA", false);
  ASSERT_TRUE(leaf65_cert);

  auto leaf87_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_87);
  auto leaf87_cert =
      GenerateCert(leaf87_key.get(), ca_key.get(), "leaf87", "CA", false);
  ASSERT_TRUE(leaf87_cert);

  // Single certs
  EXPECT_TRUE(VerifyMldsaCertificates(CertToPem(ca_cert.get())).ok());
  EXPECT_TRUE(VerifyMldsaCertificates(CertToPem(leaf44_cert.get())).ok());
  EXPECT_TRUE(VerifyMldsaCertificates(CertToPem(leaf65_cert.get())).ok());
  EXPECT_TRUE(VerifyMldsaCertificates(CertToPem(leaf87_cert.get())).ok());

  // Chain: leaf + CA
  std::string chain_pem =
      CertToPem(leaf44_cert.get()) + CertToPem(ca_cert.get());
  EXPECT_TRUE(VerifyMldsaCertificates(chain_pem).ok());

  // RSA CA and certs
  auto rsa_key = GenerateRsaKey(2048);
  ASSERT_TRUE(rsa_key);
  auto rsa_ca_cert = GenerateCert(rsa_key.get(), rsa_key.get(), "RSACA",
                                  "RSACA", true, EVP_sha256());
  ASSERT_TRUE(rsa_ca_cert);
  auto rsa_leaf_cert = GenerateCert(rsa_key.get(), rsa_key.get(), "RSALeaf",
                                    "RSACA", false, EVP_sha256());
  ASSERT_TRUE(rsa_leaf_cert);

  // Rejection of RSA cert
  auto rsa_status = VerifyMldsaCertificates(CertToPem(rsa_leaf_cert.get()));
  EXPECT_FALSE(rsa_status.ok());
  EXPECT_EQ(rsa_status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

  // Rejection of ML-DSA cert signed by RSA
  auto mldsa_by_rsa =
      GenerateCert(leaf44_key.get(), rsa_key.get(), "mldsa_by_rsa", "RSACA",
                   false, EVP_sha256());
  ASSERT_TRUE(mldsa_by_rsa);
  auto mldsa_by_rsa_status =
      VerifyMldsaCertificates(CertToPem(mldsa_by_rsa.get()));
  EXPECT_FALSE(mldsa_by_rsa_status.ok());
  EXPECT_EQ(mldsa_by_rsa_status.error_code(),
            grpc::StatusCode::UNAUTHENTICATED);

  // Empty or invalid PEM
  EXPECT_FALSE(VerifyMldsaCertificates("").ok());
  EXPECT_FALSE(VerifyMldsaCertificates("bad cert").ok());
}

TEST(MldsaTlsTest, CreateClientWithOptions) {
  auto ca_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_65);
  auto ca_cert = GenerateCert(ca_key.get(), ca_key.get(), "CA", "CA", true);
  auto client_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_65);
  auto client_cert =
      GenerateCert(client_key.get(), ca_key.get(), "client", "CA", false);

  auto rsa_key = GenerateRsaKey(2048);
  auto rsa_cert = GenerateCert(rsa_key.get(), rsa_key.get(), "rsa", "rsa",
                               false, EVP_sha256());

  AteClient::Options options;
  options.pa_target = "localhost:5000";
  options.enable_mtls = true;
  options.enable_mldsa_tls = true;
  options.pem_root_certs = CertToPem(ca_cert.get());
  options.pem_cert_chain = CertToPem(client_cert.get());
  options.pem_private_key = KeyToPem(client_key.get());

  // Successful creation with valid ML-DSA credentials
  auto client = AteClient::Create(options);
  EXPECT_NE(client, nullptr);

  // Failure when client private key is RSA
  options.pem_private_key = KeyToPem(rsa_key.get());
  EXPECT_EQ(AteClient::Create(options), nullptr);

  // Failure when root cert is RSA
  options.pem_private_key = KeyToPem(client_key.get());
  options.pem_root_certs = CertToPem(rsa_cert.get());
  EXPECT_EQ(AteClient::Create(options), nullptr);

  // Failure when client cert is RSA
  options.pem_root_certs = CertToPem(ca_cert.get());
  options.pem_cert_chain = CertToPem(rsa_cert.get());
  EXPECT_EQ(AteClient::Create(options), nullptr);

  // Success when enable_mldsa_tls is false even with RSA credentials
  options.enable_mldsa_tls = false;
  options.pem_private_key = KeyToPem(rsa_key.get());
  options.pem_root_certs = CertToPem(rsa_cert.get());
  options.pem_cert_chain = CertToPem(rsa_cert.get());
  EXPECT_NE(AteClient::Create(options), nullptr);
}

class FakePaService final : public pa::ProvisioningApplianceService::Service {
 public:
  grpc::Status InitSession(grpc::ServerContext* context,
                           const pa::InitSessionRequest* request,
                           pa::InitSessionResponse* response) override {
    response->set_sku_session_token("test-session-token");
    return grpc::Status::OK;
  }
};

TEST(MldsaTlsTest, EndToEndMldsaHandshake) {
  auto ca_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_87);
  auto ca_cert = GenerateCert(ca_key.get(), ca_key.get(), "CA", "CA", true);
  auto server_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_87);
  auto server_cert =
      GenerateCert(server_key.get(), ca_key.get(), "localhost", "CA", false);
  auto client_key = GenerateMldsaKey(EVP_PKEY_ML_DSA_87);
  auto client_cert =
      GenerateCert(client_key.get(), ca_key.get(), "client", "CA", false);

  std::string ca_pem = CertToPem(ca_cert.get());
  std::string server_cert_pem = CertToPem(server_cert.get());
  std::string server_key_pem = KeyToPem(server_key.get());
  std::string client_cert_pem = CertToPem(client_cert.get());
  std::string client_key_pem = KeyToPem(client_key.get());

  // Start gRPC server with ML-DSA-87 mTLS
  grpc::experimental::TlsServerCredentialsOptions server_tls_opts(
      std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
          ca_pem, std::vector<grpc::experimental::IdentityKeyCertPair>{
                      {server_key_pem, server_cert_pem}}));
  server_tls_opts.watch_root_certs();
  server_tls_opts.watch_identity_key_cert_pairs();
  server_tls_opts.set_cert_request_type(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  server_tls_opts.set_min_tls_version(grpc_tls_version::TLS1_3);

  FakePaService service;
  int port = 0;
  grpc::ServerBuilder builder;
  builder.AddListeningPort(
      "127.0.0.1:0", grpc::experimental::TlsServerCredentials(server_tls_opts),
      &port);
  builder.RegisterService(&service);
  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  ASSERT_NE(server, nullptr);
  ASSERT_GT(port, 0);

  AteClient::Options options;
  options.pa_target = absl::StrFormat("ipv4:127.0.0.1:%d", port);
  options.enable_mtls = true;
  options.enable_mlkem_tls = true;
  options.enable_mldsa_tls = true;
  options.pem_root_certs = ca_pem;
  options.pem_cert_chain = client_cert_pem;
  options.pem_private_key = client_key_pem;

  auto client = AteClient::Create(options);
  ASSERT_NE(client, nullptr);

  pa::InitSessionRequest req;
  req.set_sku("sival");
  req.set_sku_auth("test_password");
  pa::InitSessionResponse resp;
  grpc::Status status = client->InitSession("sival", "test_password");
  EXPECT_TRUE(status.ok()) << status.error_message();

  server->Shutdown();
}

}  // namespace
}  // namespace ate
}  // namespace provisioning
