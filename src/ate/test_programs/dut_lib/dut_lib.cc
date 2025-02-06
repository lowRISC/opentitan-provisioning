// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/test_programs/dut_lib/dut_lib.h"

#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"

namespace provisioning {
namespace test_programs {

extern "C" {
void OtLibFpgaInit(const char* fpga, const char* fpga_bitstream);
}

std::unique_ptr<DutLib> DutLib::Create(void) {
  return absl::make_unique<DutLib>();
}

absl::Status DutLib::DutInit(const std::string& fpga,
                             const std::string& fpga_bitstream) {
  LOG(INFO) << "in DutLib::DutInit";
  OtLibFpgaInit(fpga.c_str(), fpga_bitstream.c_str());
  return absl::OkStatus();
}

}  // namespace test_programs
}  // namespace provisioning
