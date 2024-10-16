// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_TESTING_TEST_HELPERS_H_
#define OPENTITAN_PROVISIONING_SRC_TESTING_TEST_HELPERS_H_

#include <cstdlib>

#include "gmock/gmock.h"
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"
#include "protobuf-matchers/protocol-buffer-matchers.h"

namespace testing {

template <typename T>
T ParseTextProto(const std::string& text) {
  T message;
  if (!::google::protobuf::TextFormat::ParseFromString(text, &message)) {
    abort();
  }
  return message;
}

// Renamespace the protobuf matchers into `testing` as that is where they'd
// normally be.
using ::protobuf_matchers::EqualsProto;
using ::protobuf_matchers::EquivToProto;
using ::protobuf_matchers::proto::Approximately;
using ::protobuf_matchers::proto::Partially;
using ::protobuf_matchers::proto::WhenDeserialized;

}  // namespace testing
#endif  // OPENTITAN_PROVISIONING_SRC_TESTING_TEST_HELPERS_H_
