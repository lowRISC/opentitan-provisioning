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
 public:
  /**
   * Factory method for instantiating and initializing this object.
   */
  static std::unique_ptr<DutLib> Create(const std::string& fpga);
  /**
   * Forbids copies or assignments of DutLib.
   */
  DutLib(const DutLib&) = delete;
  DutLib& operator=(const DutLib&) = delete;
  /**
   * Calls opentitanlib backend transport init for FPGA.
   */
  void DutFpgaLoadBitstream(const std::string& fpga_bitstream);
  /**
   * Calls opentitanlib test util to load an SRAM ELF into the DUT over JTAG.
   */
  void DutLoadSramElf(const std::string& openocd, const std::string& elf,
                      bool wait_for_done, uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to wait for a message over the SPI console.
   */
  void DutConsoleWaitForRx(const char* msg, uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to receive a message over the SPI console.
   */
  std::string DutConsoleRx(bool quiet, uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to send a message over the SPI console.
   */
  void DutConsoleTx(std::string& msg);
  /**
   * Calls opentitanlib methods to send a CP provisioning data UJSON payload
   * over the SPI console to the DUT.
   */
  void DutTxCpProvisioningData(const uint8_t* spi_frame, size_t spi_frame_size,
                               uint64_t timeout_ms);
  /**
   * Calls opentitanlib methods to receive the CP device ID UJSON payload over
   * the SPI console from the DUT.
   */
  std::string DutRxCpDeviceId(bool quiet, uint64_t timeout_ms);

 private:
  // Must match the opentitanlib UartConsole buffer size defined here:
  // https://github.com/lowRISC/opentitan/blob/673199e30f85db799df6a31c983e8e41c8afb6c8/sw/host/opentitanlib/src/uart/console.rs#L46
  static constexpr size_t kMaxRxMsgSizeInBytes = 16384;

  // Force users to call `Create` factory method.
  DutLib(void* transport) : transport_(transport){};

  void* transport_;
};

}  // namespace test_programs
}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
