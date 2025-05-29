// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/test_programs/dut_lib/dut_lib.h"

#include <google/protobuf/util/json_util.h>

#include <iomanip>
#include <string>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "src/ate/proto/dut_commands.pb.h"

namespace provisioning {
namespace test_programs {

extern "C" {
void* OtLibFpgaTransportInit(const char* fpga);
void OtLibFpgaLoadBitstream(void* transport, const char* fpga_bitstream);
void OtLibLoadSramElf(void* transport, const char* openocd, const char* elf,
                      bool wait_for_done, uint64_t timeout_ms);
void OtLibBootstrap(void* transport, const char* bin);
void OtLibWaitForGpioState(void* transport, const char* pin, bool state,
                           uint64_t timeout_ms);
void OtLibConsoleWaitForRx(void* transport, const char* msg,
                           uint64_t timeout_ms);
void OtLibConsoleRx(void* transport, bool quiet, uint64_t timeout_ms,
                    uint8_t* msg, size_t* msg_size);
void OtLibConsoleTx(void* transport, const char* msg);
void OtLibTxCpProvisioningData(void* transport, const uint8_t* spi_frame,
                               size_t spi_frame_size, uint64_t timeout_ms);
void OtLibRxCpDeviceId(void* transport, bool quiet, uint64_t timeout_ms,
                       uint8_t* cp_device_id_str,
                       size_t* cp_device_id_str_size);
void OtLibResetAndLock(void* transport, const char* openocd);
void OtLibLcTransition(void* transport, const char* openocd,
                       const uint8_t* token, size_t token_size,
                       uint32_t target_lc_state);
void OtLibTxRmaUnlockTokenHash(void* transport, const uint8_t* spi_frame,
                               size_t spi_frame_size, uint64_t timeout_ms);
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

void DutLib::DutWaitForGpioState(const char* pin, bool state,
                                 uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutWaitForGpioState";
  OtLibWaitForGpioState(transport_, pin, state, timeout_ms);
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

void DutLib::DutTxCpProvisioningData(const uint8_t* spi_frame,
                                     size_t spi_frame_size,
                                     uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutTxCpProvisioningData";
  OtLibTxCpProvisioningData(transport_, spi_frame, spi_frame_size, timeout_ms);
}

std::string DutLib::DutRxCpDeviceId(bool quiet, uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutRxCpDeviceId";
  size_t cp_device_id_str_size = kMaxRxMsgSizeInBytes;
  std::string cp_device_id_str(kMaxRxMsgSizeInBytes, '\0');
  OtLibRxCpDeviceId(
      transport_, quiet, timeout_ms,
      reinterpret_cast<uint8_t*>(const_cast<char*>(cp_device_id_str.data())),
      &cp_device_id_str_size);
  cp_device_id_str.resize(cp_device_id_str_size);
  return cp_device_id_str;
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

void DutLib::DutTxFtRmaUnlockTokenHash(const uint8_t* spi_frame,
                                       size_t spi_frame_size,
                                       uint64_t timeout_ms) {
  LOG(INFO) << "in DutLib::DutTxFtRmaUnlockTokenHash";
  OtLibTxRmaUnlockTokenHash(transport_, spi_frame, spi_frame_size, timeout_ms);
}
}  // namespace test_programs
}  // namespace provisioning
