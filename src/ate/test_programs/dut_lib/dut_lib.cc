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
void* OtLibFpgaTransportInit(const char* fpga);
void OtLibFpgaLoadBitstream(void* transport, const char* fpga_bitstream);
void OtLibLoadSramElf(void* transport, const char* openocd, const char* elf);
void OtLibConsoleWaitForRx(void* transport, const char* msg,
                           uint64_t timeout_ms);
void OtLibConsoleRx(void* transport, bool quiet, uint64_t timeout_ms,
                    uint8_t* msg, size_t* msg_size);
void OtLibConsoleTx(void* transport, const char* msg);
}

std::unique_ptr<DutLib> DutLib::Create(const std::string& fpga) {
  return absl::WrapUnique<DutLib>(
      new DutLib(OtLibFpgaTransportInit(fpga.c_str())));
}

void DutLib::DutFpgaLoadBitstream(const std::string& fpga_bitstream) {
  LOG(INFO) << "in DutLib::DutFpgaLoadBitstream";
  OtLibFpgaLoadBitstream(transport_, fpga_bitstream.c_str());
}

void DutLib::DutLoadSramElf(const std::string& openocd,
                            const std::string& elf) {
  LOG(INFO) << "in DutLib::DutLoadSramElf";
  OtLibLoadSramElf(transport_, openocd.c_str(), elf.c_str());
}

void DutLib::DutConsoleWaitForRx(const char* msg, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutConsoleWaitForRx";
  OtLibConsoleWaitForRx(transport_, msg, timeout_ms);
}

std::string DutLib::DutConsoleRx(bool quiet, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutConsoleRx";
  size_t msg_size = kMaxRxMsgSizeInBytes;
  std::string result(kMaxRxMsgSizeInBytes, '\0');
  OtLibConsoleRx(transport_, quiet, timeout_ms,
                 reinterpret_cast<uint8_t*>(const_cast<char*>(result.data())),
                 &msg_size);
  result.resize(msg_size);
  return result;
}

void DutLib::DutConsoleTx(std::string& msg) {
  LOG(INFO) << "in DutLib::DutConsoleTx";
  OtLibConsoleTx(transport_, msg.c_str());
}

}  // namespace test_programs
}  // namespace provisioning
