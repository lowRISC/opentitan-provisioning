// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage_config.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "src/ate/ate_api.h"
#include "src/ate/test_programs/dut_lib/dut_lib.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/pa/proto/pa.pb.h"
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
ABSL_FLAG(std::string, pa_target, "",
          "Endpoint address in gRPC name-syntax format, including port "
          "number. For example: \"localhost:5000\", "
          "\"ipv4:127.0.0.1:5000,127.0.0.2:5000\", or "
          "\"ipv6:[::1]:5000,[::1]:5001\".");
ABSL_FLAG(std::string, load_balancing_policy, "",
          "gRPC load balancing policy. If not set, it will be selected by "
          "the gRPC library. For example: \"round_robin\" or "
          "\"pick_first\".");
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
using provisioning::test_programs::DutLib;

absl::StatusOr<ate_client_ptr> AteClientNew(void) {
  client_options_t options;

  std::string pa_target = absl::GetFlag(FLAGS_pa_target);
  if (pa_target.empty()) {
    return absl::InvalidArgumentError(
        "--pa_target not set. This is a required argument.");
  }
  options.pa_target = pa_target.c_str();
  options.enable_mtls = absl::GetFlag(FLAGS_enable_mtls);

  std::string lb_policy = absl::GetFlag(FLAGS_load_balancing_policy);
  options.load_balancing_policy = lb_policy.c_str();

  std::string pem_private_key = absl::GetFlag(FLAGS_client_key);
  std::string pem_cert_chain = absl::GetFlag(FLAGS_client_cert);
  std::string pem_root_certs = absl::GetFlag(FLAGS_ca_root_certs);

  if (options.enable_mtls) {
    if (pem_private_key.empty() || pem_cert_chain.empty() ||
        pem_root_certs.empty()) {
      return absl::InvalidArgumentError(
          "--client_key, --client_cert, and --ca_root_certs are required "
          "arguments when --enable_mtls is set.");
    }
    options.pem_private_key = pem_private_key.c_str();
    options.pem_cert_chain = pem_cert_chain.c_str();
    options.pem_root_certs = pem_root_certs.c_str();
  }

  ate_client_ptr ate_client;
  if (CreateClient(&ate_client, &options) != 0) {
    return absl::InternalError("Failed to create ATE client.");
  }
  return ate_client;
}

absl::StatusOr<std::string> ValidateFilePathInput(std::string path) {
  std::ifstream file_stream(path);
  if (file_stream.good()) {
    return path;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Unable to open file: \"", path, "\""));
}

bool SetDiversificationString(uint8_t *diversifier, const std::string &str) {
  if (str.size() > kDiversificationStringSize) {
    return false;
  }
  memcpy(diversifier, str.data(), str.size());
  memset(diversifier + str.size(), 0, kDiversificationStringSize - str.size());
  return true;
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

  // Validate FPGA bitstream path.
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
  auto ate_client_result = AteClientNew();
  if (!ate_client_result.ok()) {
    LOG(ERROR) << ate_client_result.status().message() << std::endl;
    return -1;
  }
  ate_client_ptr ate_client = ate_client_result.value();

  // Init session with PA.
  if (InitSession(ate_client, absl::GetFlag(FLAGS_sku).c_str(),
                  absl::GetFlag(FLAGS_sku_auth_pw).c_str()) != 0) {
    LOG(ERROR) << "InitSession with PA failed.";
    return -1;
  }

  // Derive the WAS, test unlock, and test exit tokens.
  derive_token_params_t params[] = {
      {
          // WAS
          .seed = kTokenSeedSecurityHigh,
          .type = kTokenTypeRaw,
          .size = kTokenSize256,
          .diversifier = {0},
      },
      {
          // Test Unlock Token
          .seed = kTokenSeedSecurityLow,
          .type = kTokenTypeHashedLcToken,
          .size = kTokenSize128,
          .diversifier = {0},
      },
      {
          // Test Exit Token
          .seed = kTokenSeedSecurityLow,
          .type = kTokenTypeHashedLcToken,
          .size = kTokenSize128,
          .diversifier = {0},
      },
  };
  // TODO(timothytrippel): Set diversifier to "was" || CP device ID.
  if (!SetDiversificationString(params[0].diversifier, "was")) {
    LOG(ERROR) << "Failed to set diversifier for WAS.";
    return -1;
  }
  if (!SetDiversificationString(params[1].diversifier, "test_unlock")) {
    LOG(ERROR) << "Failed to set diversifier for test_unlock.";
    return -1;
  }
  if (!SetDiversificationString(params[2].diversifier, "test_exit")) {
    LOG(ERROR) << "Failed to set diversifier for test_exit.";
    return -1;
  }
  token_t tokens[3];
  if (DeriveTokens(ate_client, absl::GetFlag(FLAGS_sku).c_str(), /*count=*/3,
                   params, tokens) != 0) {
    LOG(ERROR) << "DeriveTokens failed.";
    return -1;
  }

  // Convert the tokens to a JSON payload to inject during CP.
  dut_rx_spi_frame_t spi_frame;
  if (TokensToJson(&tokens[0], &tokens[1], &tokens[2], &spi_frame) != 0) {
    LOG(ERROR) << "TokensToJson failed.";
    return -1;
  }

  // Init session with FPGA DUT and load CP provisioning firmware.
  auto dut = DutLib::Create(absl::GetFlag(FLAGS_fpga));
  dut->DutFpgaLoadBitstream(fpga_bitstream_path);
  dut->DutLoadSramElf(openocd_path, sram_elf_path, /*wait_for_done=*/false,
                      /*timeout_ms=*/1000);
  dut->DutConsoleTx("Waiting for CP provisioning data ...", spi_frame.payload,
                    kDutRxSpiFrameSizeInBytes,
                    /*timeout_ms=*/1000);
  dut_tx_spi_frame_t devid_spi_frame = {0};
  size_t num_spi_frames = 1;
  dut->DutConsoleRx("Exporting CP device ID ...", &devid_spi_frame,
                    &num_spi_frames,
                    /*skip_crc_check=*/true,
                    /*quiet=*/true,
                    /*timeout_ms=*/1000);
  device_id_bytes_t device_id_bytes = {.raw = {0}};
  if (DeviceIdFromJson(&devid_spi_frame, &device_id_bytes) != 0) {
    LOG(ERROR) << "TokensToJson failed.";
    return -1;
  }
  uint32_t *device_id_words = reinterpret_cast<uint32_t *>(device_id_bytes.raw);
  LOG(INFO) << absl::StrFormat("CP Device ID: 0x%08x%08x%08x%08x",
                               device_id_words[3], device_id_words[2],
                               device_id_words[1], device_id_words[0]);

  // Lock the chip and close session with PA.
  dut->DutResetAndLock(openocd_path);
  if (CloseSession(ate_client) != 0) {
    LOG(ERROR) << "CloseSession with PA failed.";
    return -1;
  }
  DestroyClient(ate_client);
  return 0;
}
