// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include <gmock/gmock.h>
#include <google/protobuf/util/json_util.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "src/ate/ate_api.h"
#include "src/ate/proto/dut_commands.pb.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/pa/proto/pa_mock.grpc.pb.h"
#include "src/testing/test_helpers.h"

namespace {

using testing::EqualsProto;

class AteJsonTest : public ::testing::Test {};

TEST_F(AteJsonTest, TokensToJson) {
  dut_spi_frame_t frame;
  token_t wafer_auth_secret = {0};
  token_t test_unlock_token = {0};
  token_t test_exit_token = {0};

  wafer_auth_secret.size = sizeof(uint32_t) * 8;
  test_unlock_token.size = sizeof(uint64_t) * 2;
  test_exit_token.size = sizeof(uint64_t) * 2;

  wafer_auth_secret.data[0] = 1;
  test_unlock_token.data[0] = 1;
  test_exit_token.data[0] = 1;

  EXPECT_EQ(TokensToJson(&wafer_auth_secret, &test_unlock_token,
                         &test_exit_token, &frame),
            0);

  std::string json_string =
      std::string(reinterpret_cast<char*>(frame.payload), frame.cursor);

  ot::dut_commands::TokensJSON tokens_cmd;
  google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(json_string, &tokens_cmd,
                                                  options);
  EXPECT_EQ(status.ok(), true);
  EXPECT_THAT(tokens_cmd, EqualsProto(R"pb(
                wafer_auth_secret: 1
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                wafer_auth_secret: 0
                test_unlock_token_hash: 1
                test_unlock_token_hash: 0
                test_exit_token_hash: 1
                test_exit_token_hash: 0
              )pb"));
}

TEST_F(AteJsonTest, DeviceIdFromJson) {
  ot::dut_commands::DeviceIdJSON device_id_cmd;
  device_id_cmd.add_cp_device_id(0x12345678);
  device_id_cmd.add_cp_device_id(0x0);
  device_id_cmd.add_cp_device_id(0x0);
  device_id_cmd.add_cp_device_id(0x0);

  std::string command;
  google::protobuf::util::JsonOptions options;
  options.add_whitespace = false;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names = true;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(device_id_cmd, &command,
                                                  options);
  EXPECT_EQ(status.ok(), true);

  dut_spi_frame_t frame;
  memcpy(frame.payload, command.data(), command.size());
  frame.cursor = command.size();

  device_id_bytes_t device_id;
  EXPECT_EQ(DeviceIdFromJson(&frame, &device_id), 0);
  EXPECT_THAT(
      device_id.raw,
      testing::ElementsAreArray(
          {0x78, 0x56, 0x34, 0x12, 0x0,  0x0,  0x0,  0x0,  0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
}

TEST_F(AteJsonTest, RmaToken) {
  token_t rma_token = {0};
  rma_token.size = sizeof(uint64_t) * 2;
  rma_token.data[0] = 0x11;
  rma_token.data[1] = 0x22;

  dut_spi_frame_t frame;
  EXPECT_EQ(RmaTokenToJson(&rma_token, &frame), 0);

  std::string json_string =
      std::string(reinterpret_cast<char*>(frame.payload), frame.cursor);

  // Use the proto representation of RmaTokenJSON to verify the
  // JSON string.
  ot::dut_commands::RmaTokenJSON rma_hash_cmd;
  google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(json_string, &rma_hash_cmd,
                                                  options);
  EXPECT_EQ(status.ok(), true);
  EXPECT_THAT(rma_hash_cmd, EqualsProto(R"pb(
                hash: 8721 hash: 0
              )pb"));

  token_t rma_token_got = {0};
  EXPECT_EQ(RmaTokenFromJson(&frame, &rma_token_got), 0);
  EXPECT_THAT(rma_token_got.data, testing::ElementsAreArray(
                                      rma_token.data, sizeof(rma_token.data)));
  EXPECT_EQ(rma_token_got.size, sizeof(uint64_t) * 2);
}

TEST_F(AteJsonTest, PersoBlob) {
  perso_blob_t blob = {0};
  blob.num_objects = 1;
  blob.next_free = 0;

  // Fill the blob with random data for testing.
  for (size_t i = 0; i < sizeof(blob.body); ++i) {
    blob.body[i] = static_cast<uint8_t>((i | 0x80) & 0xFF);
  }

  dut_spi_frame_t frames[16] = {0};
  size_t num_frames = sizeof(frames) / sizeof(frames[0]);
  EXPECT_EQ(PersoBlobToJson(&blob, frames, &num_frames), 0);
  EXPECT_EQ(num_frames, 11);

  perso_blob_t blob_got = {0};
  EXPECT_EQ(PersoBlobFromJson(frames, num_frames, &blob_got), 0);
  EXPECT_EQ(blob_got.num_objects, 1);
  EXPECT_EQ(blob_got.next_free, 0);
  EXPECT_THAT(blob_got.body,
              testing::ElementsAreArray(blob.body, sizeof(blob.body)));
}

}  // namespace
