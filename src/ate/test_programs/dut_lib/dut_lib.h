// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_

#include <memory>
#include <string>

namespace provisioning {
namespace test_programs {

class DutLib {
 private:
  // Must match the opentitanlib UartConsole buffer size defined here:
  // https://github.com/lowRISC/opentitan/blob/673199e30f85db799df6a31c983e8e41c8afb6c8/sw/host/opentitanlib/src/uart/console.rs#L46
  static constexpr size_t kMaxRxMsgSizeInBytes = 16384;

  void* transport_;
  char console_msg_buf_[kMaxRxMsgSizeInBytes];

  // Force users to call `Create` factory method.
  DutLib(void* transport) : transport_(transport) {};

 public:
  // Forbids copies or assignments of DutLib.
  DutLib(const DutLib&) = delete;
  DutLib& operator=(const DutLib&) = delete;

  static std::unique_ptr<DutLib> Create(const std::string& fpga);

  // Calls opentitanlib backend transport init for FPGA.
  void DutFpgaLoadBitstream(const std::string& fpga_bitstream);

  // Calls opentitanlib test util to load an SRAM ELF into the DUT over JTAG.
  void DutLoadSramElf(const std::string& openocd, const std::string& elf);

  // Calls opentitanlib test util to wait for a message over the SPI console.
  void DutConsoleWaitForRx(const char*, uint64_t timeout_ms);

  // Calls opentitanlib test util to receive a message over the SPI console.
  std::string DutConsoleRx(bool quiet, uint64_t timeout_ms);

  // Calls opentitanlib test util to send a message over the SPI console.
  void DutConsoleTx(std::string& msg);
};

}  // namespace test_programs
}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
