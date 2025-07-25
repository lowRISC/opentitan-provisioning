// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_

#include <memory>
#include <string>

#include "src/ate/ate_api.h"

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
   * Calls opentitanlib to bootstrap a binary into the DUT's flash over SPI.
   */
  void DutBootstrap(const std::string& bin);
  /**
   * Calls opentitanlib test util to wait for a message over the SPI console.
   */
  void DutConsoleWaitForRx(const char* msg, uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to receive a message over the SPI console.
   */
  void DutConsoleRx(const std::string& sync_msg, dut_spi_frame_t* spi_frames,
                    size_t* num_frames, bool skip_crc_check, bool quiet,
                    uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to send a message over the SPI console.
   */
  void DutConsoleTx(const std::string& sync_msg, const uint8_t* spi_frame,
                    size_t spi_frame_size, uint64_t timeout_ms);
  /**
   * Calls opentitanlib test util to execute a life cycle transition to
   * TestLocked0 (from TestUnlocked0).
   */
  void DutResetAndLock(const std::string& openocd);
  /**
   * Calls opentitanlib test util to execute a life cycle transition to
   * TestUnlocked* (from TestLocked*).
   */
  void DutLcTransition(const std::string& openocd, const uint8_t* token,
                       size_t token_size, uint32_t target_lc_state);
  /**
   * Calls opentitanlib test utils to reset the DUT and wait for a ROM_EXT and
   * owner firmware boot message to appear over the console to indicate the DUT
   * has been provisioned successfully.
   */
  void DutCheckTransportImgBoot(const char* owner_fw_boot_msg,
                                uint64_t timeout_ms);

 private:
  // Must be 2x the opentitanlib UartConsole buffer size defined here:
  // https://github.com/lowRISC/opentitan/blob/673199e30f85db799df6a31c983e8e41c8afb6c8/sw/host/opentitanlib/src/uart/console.rs#L46
  // to account for whitespace padding.
  static constexpr size_t kMaxRxMsgSizeInBytes = 65536;

  // Force users to call `Create` factory method.
  DutLib(void* transport) : transport_(transport){};

  void* transport_;
};

}  // namespace test_programs
}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_ATE_TEST_PROGRAMS_DUT_LIB_DUT_LIB_H_
