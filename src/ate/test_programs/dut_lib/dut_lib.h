// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_

#include <string>

#include "absl/status/status.h"

namespace provisioning {
namespace test_programs {

class DutLib {
 public:
  DutLib(){};

  // Forbids copies or assignments of DutLib.
  DutLib(const DutLib&) = delete;
  DutLib& operator=(const DutLib&) = delete;

  static std::unique_ptr<DutLib> Create(void);

  // Calls opentitanlib backend transport init for FPGA.
  absl::Status DutInit(const std::string& fpga,
                       const std::string& fpga_bitstream);
};

}  // namespace test_programs
}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
