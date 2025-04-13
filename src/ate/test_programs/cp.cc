// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage_config.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_replace.h"
#include "src/ate/ate_client.h"
#include "src/ate/test_programs/dut_lib/dut_lib.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/version/version.h"

/**
 * DUT configuration flags.
 */
ABSL_FLAG(std::string, fpga, "", "FPGA platform to use.");
ABSL_FLAG(std::string, bitstream,
          "third_party/lowrisc/ot_bitstreams/cp_$fpga.bit",
          "Bitstream to load.");
ABSL_FLAG(std::string, openocd, "", "OpenOCD binary path.");
ABSL_FLAG(std::string, cp_sram_elf, "", "CP SRAM ELF (device binary).");

/**
 * PA configuration flags.
 */
ABSL_FLAG(std::string, pa_socket, "", "host:port of the PA server.");
ABSL_FLAG(std::string, sku, "", "SKU string to initialize the PA session.");
ABSL_FLAG(std::string, sku_auth_pw, "",
          "SKU authorization password string to initialize the PA session.");

/**
 * mTLS configuration flags.
 */
ABSL_FLAG(bool, enable_mtls, false, "Enable mTLS secure channel.");
ABSL_FLAG(std::string, client_key, "",
          "File path to the PEM encoding of the client's private key.");
ABSL_FLAG(std::string, client_cert, "",
          "File path to the PEM encoding of the  client's certificate chain.");
ABSL_FLAG(std::string, ca_root_certs, "",
          "File path to the PEM encoding of the server root certificates.");

namespace {
using provisioning::VersionFormatted;
using provisioning::ate::AteClient;
using provisioning::test_programs::DutLib;

// Returns `filename` content in a std::string format
absl::StatusOr<std::string> ReadFile(const std::string &filename) {
  auto output_stream = std::ostringstream();
  std::ifstream file_stream(filename);
  if (!file_stream.is_open()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unable to open file: \"", filename, "\""));
  }
  output_stream << file_stream.rdbuf();
  return output_stream.str();
}

absl::StatusOr<AteClient::Options> ValidateAteClientOptions(void) {
  AteClient::Options options;
  options.pa_socket = absl::GetFlag(FLAGS_pa_socket);
  options.enable_mtls = absl::GetFlag(FLAGS_enable_mtls);

  // If mTLS is enabled, load key and certs.
  if (options.enable_mtls) {
    std::unordered_map<absl::Flag<std::string> *, std::string *> pem_options = {
        {&FLAGS_client_key, &options.pem_private_key},
        {&FLAGS_client_cert, &options.pem_cert_chain},
        {&FLAGS_ca_root_certs, &options.pem_root_certs},
    };
    for (auto opt : pem_options) {
      // Check the required filepath flag was provided.
      std::string filename = absl::GetFlag(*opt.first);
      if (filename.empty()) {
        return absl::InvalidArgumentError(
            absl::StrCat("--", absl::GetFlagReflectionHandle(*opt.first).Name(),
                         " not set. This is a required argument when "
                         "--enable_mtls is set to true."));
      }
      // Check the required filepath is valid by attempting to read it.
      auto result = ReadFile(filename);
      if (!result.ok()) {
        return absl::InvalidArgumentError(
            absl::StrCat("--", absl::GetFlagReflectionHandle(*opt.first).Name(),
                         " ", result.status().message()));
      }
      *opt.second = result.value();
    }
  }
  return options;
}

absl::StatusOr<std::string> ValidateFilePathInput(std::string path) {
  std::ifstream file_stream(path);
  if (file_stream.good()) {
    return path;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Unable to open file: \"", path, "\""));
}
}  // namespace

int main(int argc, char **argv) {
  // Parse cmd line args.
  absl::FlagsUsageConfig config;
  absl::SetFlagsUsageConfig(config);
  absl::ParseCommandLine(argc, argv);

  // Set version string.
  config.version_string = &VersionFormatted;
  LOG(INFO) << VersionFormatted();

  // Validate cmd line args.
  auto ate_opts_result = ValidateAteClientOptions();
  if (!ate_opts_result.ok()) {
    LOG(ERROR) << ate_opts_result.status().message() << std::endl;
    return -1;
  }
  // Validate FPGA bitstream path.
  AteClient::Options ate_options = ate_opts_result.value();
  auto bitstream_result = ValidateFilePathInput(absl::StrReplaceAll(
      absl::GetFlag(FLAGS_bitstream), {{"$fpga", absl::GetFlag(FLAGS_fpga)}}));
  if (!bitstream_result.ok()) {
    LOG(ERROR) << bitstream_result.status().message() << std::endl;
    return -1;
  }
  std::string fpga_bitstream_path = bitstream_result.value();
  // Validate OpenOCD path.
  auto openocd_result = ValidateFilePathInput(absl::GetFlag(FLAGS_openocd));
  if (!openocd_result.ok()) {
    LOG(ERROR) << openocd_result.status().message() << std::endl;
    return -1;
  }
  std::string openocd_path = openocd_result.value();
  // Validate SRAM ELF path.
  auto sram_elf_result =
      ValidateFilePathInput(absl::GetFlag(FLAGS_cp_sram_elf));
  if (!sram_elf_result.ok()) {
    LOG(ERROR) << sram_elf_result.status().message() << std::endl;
    return -1;
  }
  std::string sram_elf_path = sram_elf_result.value();

  // Instantiate an ATE client (gateway to PA).
  auto ate = AteClient::Create(ate_options);

  // Init session with PA.
  grpc::Status pa_status = ate->InitSession(absl::GetFlag(FLAGS_sku),
                                            absl::GetFlag(FLAGS_sku_auth_pw));
  if (!pa_status.ok()) {
    LOG(ERROR) << "InitSession with PA failed " << pa_status.error_code()
               << ": " << pa_status.error_message() << std::endl;
    return -1;
  }

  // TODO: replace hardcoded tokens with ones generated by PA/SPM.
  std::string was(
      "0x11111111_22222222_33333333_44444444_55555555_66666666_77777777_"
      "88888888");
  std::string test_unlock_token("0x11111111_22222222_33333333_44444444");
  std::string test_exit_token("0x11111111_22222222_33333333_44444444");

  // Init session with FPGA DUT and load CP provisioning firmware.
  auto dut = DutLib::Create(absl::GetFlag(FLAGS_fpga));
  dut->DutFpgaLoadBitstream(fpga_bitstream_path);
  dut->DutLoadSramElf(openocd_path, sram_elf_path);
  dut->DutTxCpProvisioningData(&was, &test_unlock_token, &test_exit_token,
                               /*timeout_ms=*/1000);
  std::string cp_device_id_str = dut->DutRxCpDeviceId(/*quiet=*/false,
                                                      /*timeout_ms=*/1000);
  LOG(INFO) << "CP Device ID: " << cp_device_id_str << std::endl;

  // Close session with PA.
  pa_status = ate->CloseSession();
  if (!pa_status.ok()) {
    LOG(ERROR) << "CloseSession failed with " << pa_status.error_code() << ": "
               << pa_status.error_message() << std::endl;
    return -1;
  }

  return 0;
}
