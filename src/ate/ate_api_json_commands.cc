// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include <google/protobuf/util/json_util.h>

#include <algorithm>

#include "absl/log/log.h"
#include "src/ate/ate_api.h"
#include "src/ate/proto/dut_commands.pb.h"

namespace {
int SpiFrameSet(dut_spi_frame_t *frame, const std::string &payload) {
  if (frame == nullptr) {
    LOG(ERROR) << "Invalid result buffer";
    return -1;
  }

  // This is an unlikely error.
  if (payload.size() > sizeof(frame->payload)) {
    LOG(ERROR) << "Output buffer size is too small"
               << " (expected: >=" << payload.size()
               << ", got: " << sizeof(frame->payload) << ")";
    return -1;
  }

  memcpy(frame->payload, payload.data(), payload.size());
  std::fill(frame->payload + payload.size(),
            frame->payload + sizeof(frame->payload), ' ');
  frame->cursor = payload.size();
  return 0;
}

inline uint32_t ByteSwap32(uint32_t value) {
  return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
         ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

inline uint64_t ByteSwap64(uint64_t value) {
  return ((value & 0xFF00000000000000ULL) >> 56) |
         ((value & 0x00FF000000000000ULL) >> 40) |
         ((value & 0x0000FF0000000000ULL) >> 24) |
         ((value & 0x000000FF00000000ULL) >> 8) |
         ((value & 0x00000000FF000000ULL) << 8) |
         ((value & 0x0000000000FF0000ULL) << 24) |
         ((value & 0x000000000000FF00ULL) << 40) |
         ((value & 0x00000000000000FFULL) << 56);
}

}  // namespace

DLLEXPORT int TokensToJson(const token_t *wafer_auth_secret,
                           const token_t *test_unlock_token,
                           const token_t *test_exit_token,
                           dut_spi_frame_t *result) {
  if (result == nullptr) {
    LOG(ERROR) << "Invalid result buffer";
    return -1;
  }

  ot::dut_commands::TokensJSON tokens_cmd;
  if (wafer_auth_secret == nullptr ||
      wafer_auth_secret->size != sizeof(uint32_t) * 8) {
    LOG(ERROR) << "Invalid wafer auth secret" << wafer_auth_secret->size;
    return -1;
  }
  const uint32_t *was_ptr =
      reinterpret_cast<const uint32_t *>(wafer_auth_secret->data);
  for (size_t i = 0; i < 8; ++i) {
    tokens_cmd.add_wafer_auth_secret(ByteSwap32(was_ptr[i]));
  }

  if (test_unlock_token == nullptr ||
      test_unlock_token->size != sizeof(uint64_t) * 2) {
    LOG(ERROR) << "Invalid test unlock token" << test_unlock_token->size;
    return -1;
  }
  const uint64_t *test_unlock_token_ptr =
      reinterpret_cast<const uint64_t *>(test_unlock_token->data);
  for (size_t i = 0; i < 2; ++i) {
    tokens_cmd.add_test_unlock_token_hash(ByteSwap64(test_unlock_token_ptr[i]));
  }

  if (test_exit_token == nullptr ||
      test_exit_token->size != sizeof(uint64_t) * 2) {
    LOG(ERROR) << "Invalid test exit token" << test_exit_token->size;
    return -1;
  }
  const uint64_t *test_exit_token_ptr =
      reinterpret_cast<const uint64_t *>(test_exit_token->data);
  for (size_t i = 0; i < 2; ++i) {
    tokens_cmd.add_test_exit_token_hash(ByteSwap64(test_exit_token_ptr[i]));
  }

  // Convert the provisioning data to a JSON string.
  std::string command;
  google::protobuf::util::JsonOptions options;
  options.add_whitespace = false;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names = true;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(tokens_cmd, &command,
                                                  options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to convert tokens to JSON: " << status.ToString();
    return -1;
  }

  return SpiFrameSet(result, command);
}

DLLEXPORT int DeviceIdFromJson(const dut_spi_frame_t *frame,
                               device_id_bytes_t *device_id) {
  if (frame == nullptr || device_id == nullptr) {
    LOG(ERROR) << "Invalid input buffer";
    return -1;
  }

  ot::dut_commands::DeviceIdJSON device_id_cmd;
  google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;
  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(
          std::string(reinterpret_cast<const char *>(frame->payload),
                      frame->cursor),
          &device_id_cmd, options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to parse JSON: " << status.ToString();
    return -1;
  }

  for (int i = 0; i < device_id_cmd.cp_device_id_size(); ++i) {
    uint32_t value = device_id_cmd.cp_device_id(i);
    memcpy(device_id->raw + i * sizeof(uint32_t), &value, sizeof(uint32_t));
  }

  return 0;
}

DLLEXPORT int RmaTokenToJson(const token_t *rma_token,
                             dut_spi_frame_t *result) {
  if (result == nullptr) {
    LOG(ERROR) << "Invalid result buffer";
    return -1;
  }

  ot::dut_commands::RmaTokenJSON rma_hash_cmd;
  if (rma_token == nullptr || rma_token->size != sizeof(uint64_t) * 2) {
    LOG(ERROR) << "Invalid RMA token" << rma_token->size;
    return -1;
  }
  const uint64_t *rma_token_ptr =
      reinterpret_cast<const uint64_t *>(rma_token->data);
  for (size_t i = 0; i < 2; ++i) {
    rma_hash_cmd.add_hash(rma_token_ptr[i]);
  }

  std::string command;
  google::protobuf::util::JsonOptions options;
  options.add_whitespace = false;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names = true;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(rma_hash_cmd, &command,
                                                  options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to convert token hash command to JSON: "
               << status.ToString();
    return -1;
  }

  return SpiFrameSet(result, command);
}

DLLEXPORT int RmaTokenFromJson(const dut_spi_frame_t *frame,
                               token_t *rma_token) {
  if (frame == nullptr || rma_token == nullptr) {
    LOG(ERROR) << "Invalid input buffer";
    return -1;
  }

  ot::dut_commands::RmaTokenJSON rma_hash_cmd;
  google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;

  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(
          std::string(reinterpret_cast<const char *>(frame->payload),
                      frame->cursor),
          &rma_hash_cmd, options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to parse JSON: " << status.ToString();
    return -1;
  }

  if (rma_hash_cmd.hash_size() != 2) {
    LOG(ERROR) << "Invalid RMA token hash size" << rma_hash_cmd.hash_size();
    return -1;
  }

  for (size_t i = 0; i < rma_hash_cmd.hash_size(); ++i) {
    uint64_t value = rma_hash_cmd.hash(i);
    memcpy(rma_token->data + i * sizeof(uint64_t), &value, sizeof(uint64_t));
  }
  rma_token->size = sizeof(uint64_t) * rma_hash_cmd.hash_size();

  return 0;
}

DLLEXPORT int PersoBlobToJson(const perso_blob_t *blob, dut_spi_frame_t *result,
                              size_t *num_frames) {
  if (result == nullptr) {
    LOG(ERROR) << "Invalid result buffer";
    return -1;
  }

  if (num_frames == nullptr) {
    LOG(ERROR) << "Invalid num_frames buffer";
    return -1;
  }

  ot::dut_commands::PersoBlobJSON blob_cmd;
  if (blob == nullptr || blob->num_objects == 0 ||
      blob->next_free > sizeof(blob->body)) {
    LOG(ERROR) << "Invalid perso blob" << blob->num_objects << ", "
               << blob->next_free;
    return -1;
  }
  blob_cmd.set_num_objs(blob->num_objects);
  blob_cmd.set_next_free(blob->next_free);

  for (size_t i = 0; i < sizeof(blob->body); ++i) {
    blob_cmd.add_body(blob->body[i]);
  }

  std::string command;
  google::protobuf::util::JsonOptions options;
  options.add_whitespace = false;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names = true;
  google::protobuf::util::Status status =
      google::protobuf::util::MessageToJsonString(blob_cmd, &command, options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to convert token hash command to JSON: "
               << status.ToString();
    return -1;
  }

  const size_t kNumFramesExpected =
      (command.size() + kDutSpiFrameSize - 1) / kDutSpiFrameSize;
  const size_t kDutSpiFrameSize = sizeof(result[0].payload);

  if (*num_frames < kNumFramesExpected) {
    LOG(ERROR) << "Output buffer size is too small"
               << " (expected: >= " << kNumFramesExpected
               << ", got: " << *num_frames << ")";
    return -1;
  }

  for (size_t i = 0; i < kNumFramesExpected; ++i) {
    size_t offset = i * kDutSpiFrameSize;
    size_t size = std::min(kDutSpiFrameSize, command.size() - offset);
    if (size == 0) {
      break;
    }
    result[i].cursor = size;
    memcpy(result[i].payload, command.data() + offset, size);
  }

  *num_frames = kNumFramesExpected;
  return 0;
}

DLLEXPORT int PersoBlobFromJson(const dut_spi_frame_t *frames,
                                size_t num_frames, perso_blob_t *blob) {
  if (frames == nullptr || num_frames == 0 || blob == nullptr) {
    LOG(ERROR) << "Invalid input buffer";
    return -1;
  }

  ot::dut_commands::PersoBlobJSON blob_cmd;
  google::protobuf::util::JsonParseOptions options;
  options.ignore_unknown_fields = true;

  std::string json_str;
  for (size_t i = 0; i < num_frames; ++i) {
    json_str.append(std::string(
        reinterpret_cast<const char *>(frames[i].payload), frames[i].cursor));
  }

  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(json_str, &blob_cmd, options);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to parse JSON: " << status.ToString();
    return -1;
  }

  blob->num_objects = blob_cmd.num_objs();
  blob->next_free = blob_cmd.next_free();

  for (size_t i = 0; i < sizeof(blob->body); ++i) {
    blob->body[i] = blob_cmd.body(i);
  }

  return 0;
}
