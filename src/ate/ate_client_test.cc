// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_client.h"

#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/pa/proto/pa_mock.grpc.pb.h"
#include "src/testing/test_helpers.h"

namespace provisioning {
namespace ate {
namespace {

using pa::CreateKeyAndCertRequest;
using pa::CreateKeyAndCertResponse;
using pa::DeriveSymmetricKeysRequest;
using pa::DeriveSymmetricKeysResponse;
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

TEST_F(AteTest, CreateKeyAndCertCallsServer) {
  // Response that will be sent back for CreateKeyAndCert.
  auto response = ParseTextProto<CreateKeyAndCertResponse>(R"pb(
    keys: { cert: { blob: "fake-cert-blob" } })pb");

  // Expect CreateKeyAndCert to be called.
  // The 2nd arg is expected to be a protobuf with the `sku` field.
  // We'll return the `response` struct and a status of `OK`.
  EXPECT_CALL(*pa_service_, CreateKeyAndCert(_, EqualsProto(R"pb(
                                               sku: "abc123"
                                             )pb"),
                                             _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(grpc::Status::OK)));

  // Call the AteClient and verify it returns OK with the expected response.
  CreateKeyAndCertResponse result;
  uint8_t serial[] = {};
  EXPECT_THAT(
      ate_->CreateKeyAndCert("abc123", serial, sizeof(serial), &result).ok(),
      IsTrue());
  EXPECT_THAT(result, EqualsProto(response));
}

TEST_F(AteTest, EndorseCerts) {
  // Response that will be sent back for EndorseCerts.
  auto response = ParseTextProto<EndorseCertsResponse>(R"pb(
    certs: { blob: "fake-cert-blob" })pb");

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

TEST_F(AteTest, DeriveSymmetricKeys) {
  // Response that will be sent back for DeriveSymmetricKeys.
  auto response = ParseTextProto<DeriveSymmetricKeysResponse>(
      R"pb(
        keys: { key: "foobar" }
      )pb");

  // Expect DeriveSymmetricKeys to be called.
  // The 2nd arg is expected to be a protobuf with the `sku` field.
  // We'll return the `response` struct and a status of `OK`.
  EXPECT_CALL(*pa_service_, DeriveSymmetricKeys(_, EqualsProto(R"pb(
                                                  sku: "abc123"
                                                )pb"),
                                                _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(grpc::Status::OK)));

  DeriveSymmetricKeysRequest request;
  request.set_sku("abc123");

  // Call the AteClient and verify it returns OK with the expected response.
  pa::DeriveSymmetricKeysResponse result;
  EXPECT_THAT(ate_->DeriveSymmetricKeys(request, &result).ok(), IsTrue());
  EXPECT_THAT(result, EqualsProto(response));
}

}  // namespace
}  // namespace ate
}  // namespace provisioning
