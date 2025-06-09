// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/test_programs/dut_lib/dut_lib.h"

#include <google/protobuf/util/json_util.h>

#include <iomanip>
#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "src/ate/ate_api.h"
#include "src/ate/proto/dut_commands.pb.h"

namespace provisioning {
namespace test_programs {

extern "C" {
void* OtLibFpgaTransportInit(const char* fpga);
void OtLibFpgaLoadBitstream(void* transport, const char* fpga_bitstream);
void OtLibLoadSramElf(void* transport, const char* openocd, const char* elf,
                      bool wait_for_done, uint64_t timeout_ms);
void OtLibBootstrap(void* transport, const char* bin);
void OtLibConsoleWaitForRx(void* transport, const char* msg,
                           uint64_t timeout_ms);
void OtLibConsoleRx(void* transport, const char* sync_msg,
                    dut_spi_frame_t* spi_frames, size_t* num_frames,
                    bool skip_crc_check, bool quiet, uint64_t timeout_ms);
void OtLibConsoleTx(void* transport, const char* sync_msg,
                    const uint8_t* spi_frame, size_t spi_frame_size,
                    uint64_t timeout_ms);
void OtLibResetAndLock(void* transport, const char* openocd);
void OtLibLcTransition(void* transport, const char* openocd,
                       const uint8_t* token, size_t token_size,
                       uint32_t target_lc_state);
}

std::unique_ptr<DutLib> DutLib::Create(const std::string& fpga) {
  return absl::WrapUnique<DutLib>(
      new DutLib(OtLibFpgaTransportInit(fpga.c_str())));
}

void DutLib::DutFpgaLoadBitstream(const std::string& fpga_bitstream) {
  LOG(INFO) << "in DutLib::DutFpgaLoadBitstream";
  OtLibFpgaLoadBitstream(transport_, fpga_bitstream.c_str());
}

void DutLib::DutLoadSramElf(const std::string& openocd, const std::string& elf,
                            bool wait_for_done, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutLoadSramElf";
  OtLibLoadSramElf(transport_, openocd.c_str(), elf.c_str(), wait_for_done,
                   timeout_ms);
}

void DutLib::DutBootstrap(const std::string& bin) {
  LOG(INFO) << "in DutLib::DutBootstrap";
  OtLibBootstrap(transport_, bin.c_str());
}

void DutLib::DutConsoleWaitForRx(const char* msg, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutConsoleWaitForRx";
  OtLibConsoleWaitForRx(transport_, msg, timeout_ms);
}

void DutLib::DutConsoleRx(const std::string& sync_msg,
                          dut_spi_frame_t* spi_frames, size_t* num_frames,
                          bool skip_crc_check, bool quiet,
                          uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutConsoleRx";
  OtLibConsoleRx(transport_, sync_msg.c_str(), spi_frames, num_frames,
                 skip_crc_check, quiet, timeout_ms);
}

void DutLib::DutConsoleTx(const std::string& sync_msg, const uint8_t* spi_frame,
                          size_t spi_frame_size, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutConsoleTx";
  OtLibConsoleTx(transport_, sync_msg.c_str(), spi_frame, spi_frame_size,
                 timeout_ms);
}

void DutLib::DutResetAndLock(const std::string& openocd) {
  LOG(INFO) << "in DutLib::DutResetAndLock";
  OtLibResetAndLock(transport_, openocd.c_str());
}

void DutLib::DutLcTransition(const std::string& openocd, const uint8_t* token,
                             size_t token_size, uint32_t target_lc_state) {
  LOG(INFO) << "in DutLib::DutLcTransition";
  OtLibLcTransition(transport_, openocd.c_str(), token, token_size,
                    target_lc_state);
}

}  // namespace test_programs
}  // namespace provisioning
