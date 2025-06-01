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
#include "absl/strings/str_replace.h"
#include "external/lowrisc_opentitan/sw/device/lib/dif/dif_lc_ctrl.h"
#include "src/ate/ate_api.h"
#include "src/ate/test_programs/dut_lib/dut_lib.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/pa/proto/pa.pb.h"
#include "src/version/version.h"

/**
 * DUT configuration flags.
 */
ABSL_FLAG(std::string, fpga, "", "FPGA platform to use.");
ABSL_FLAG(std::string, openocd, "", "OpenOCD binary path.");
ABSL_FLAG(std::string, ft_individualization_elf, "",
          "FT Individualization ELF (device binary).");
ABSL_FLAG(std::string, ft_personalize_bin, "",
          "FT Personalize Binary (device binary).");
ABSL_FLAG(std::string, ft_fw_bundle_bin, "",
          "FT Personalize / Transport image bundle (device binary).");

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

absl::StatusOr<ate_client_ptr> AteClientNew(void) {
  client_options_t options;

  std::string pa_socket = absl::GetFlag(FLAGS_pa_socket);
  if (pa_socket.empty()) {
    return absl::InvalidArgumentError(
        "--pa_socket not set. This is a required argument.");
  }
  options.pa_socket = pa_socket.c_str();
  options.enable_mtls = absl::GetFlag(FLAGS_enable_mtls);

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
  CreateClient(&ate_client, &options);
  if (ate_client == nullptr) {
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

std::string BytesToHexStr(const char *bytes, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2)
       << static_cast<int>(static_cast<unsigned char>(bytes[i]));
  }
  return ss.str();
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

  // Validate OpenOCD path.
  auto openocd_result = ValidateFilePathInput(absl::GetFlag(FLAGS_openocd));
  if (!openocd_result.ok()) {
    LOG(ERROR) << openocd_result.status().message() << std::endl;
    return -1;
  }
  std::string openocd_path = openocd_result.value();
  // Validate FT firmware binary paths.
  auto ft_individ_elf_result =
      ValidateFilePathInput(absl::GetFlag(FLAGS_ft_individualization_elf));
  if (!ft_individ_elf_result.ok()) {
    LOG(ERROR) << ft_individ_elf_result.status().message() << std::endl;
    return -1;
  }
  std::string ft_individ_elf_path = ft_individ_elf_result.value();
  auto ft_perso_bin_result =
      ValidateFilePathInput(absl::GetFlag(FLAGS_ft_personalize_bin));
  if (!ft_perso_bin_result.ok()) {
    LOG(ERROR) << ft_perso_bin_result.status().message() << std::endl;
    return -1;
  }
  std::string ft_perso_bin_path = ft_perso_bin_result.value();
  auto ft_fw_bundle_result =
      ValidateFilePathInput(absl::GetFlag(FLAGS_ft_fw_bundle_bin));
  if (!ft_fw_bundle_result.ok()) {
    LOG(ERROR) << ft_fw_bundle_result.status().message() << std::endl;
    return -1;
  }
  std::string ft_fw_bundle_path = ft_fw_bundle_result.value();

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

  // Init session with FPGA DUT.
  //
  // Note: we do not reload the bitstream as the CP test program should be run
  // before running this test program.
  auto dut = DutLib::Create(absl::GetFlag(FLAGS_fpga));

  // Regenerate the test tokens.
  derive_token_params_t params[] = {
      {
          // Test Unlock Token
          .seed = kTokenSeedSecurityLow,
          .type = kTokenTypeRaw,
          .size = kTokenSize128,
          .diversifier = {0},
      },
      {
          // Test Exit Token
          .seed = kTokenSeedSecurityLow,
          .type = kTokenTypeRaw,
          .size = kTokenSize128,
          .diversifier = {0},
      },
  };
  if (!SetDiversificationString(params[0].diversifier, "test_unlock")) {
    LOG(ERROR) << "Failed to set diversifier for test_unlock.";
    return -1;
  }
  if (!SetDiversificationString(params[1].diversifier, "test_exit")) {
    LOG(ERROR) << "Failed to set diversifier for test_exit.";
    return -1;
  }
  constexpr size_t kNumTokens = 2;
  token_t tokens[kNumTokens];
  if (DeriveTokens(ate_client, absl::GetFlag(FLAGS_sku).c_str(),
                   /*count=*/kNumTokens, params, tokens) != 0) {
    LOG(ERROR) << "DeriveTokens failed.";
    return -1;
  }

  // Generate the RMA unlock token hash.
  generate_token_params_t rma_token_params = {
      .type = kTokenTypeHashedLcToken,
      .size = kTokenSize128,
      .diversifier = {0},
  };
  if (!SetDiversificationString(rma_token_params.diversifier, "rma")) {
    LOG(ERROR) << "Failed to set diversifier for RMA.";
    return -1;
  }
  token_t rma_token;
  wrapped_seed_t wrapped_rma_token_seed;
  if (GenerateTokens(ate_client, absl::GetFlag(FLAGS_sku).c_str(), /*count=*/1,
                     &rma_token_params, &rma_token,
                     &wrapped_rma_token_seed) != 0) {
    LOG(ERROR) << "GenerateTokens failed.";
    return -1;
  }
  dut_spi_frame_t rma_token_spi_frame;
  if (RmaTokenToJson(&rma_token, &rma_token_spi_frame) != 0) {
    LOG(ERROR) << "RmaTokenToJson failed.";
    return -1;
  }

  // Generate CA serial numbers.
  // TODO(timothytrippel): retrieve the serial numbers from the CA when #186
  // merges.
  ca_serial_number_t dice_ca_sn = {0};
  ca_serial_number_t aux_ca_sn = {0};
  dut_spi_frame_t ca_serial_numbers_spi_frame;
  if (CaSerialNumbersToJson(&dice_ca_sn, &aux_ca_sn,
                            &ca_serial_numbers_spi_frame) != 0) {
    LOG(ERROR) << "CaSerialNumbersToJson failed.";
    return -1;
  }

  // Unlock the chip and run the FT individualization firmware.
  dut->DutLcTransition(openocd_path, tokens[0].data, kTokenSize128,
                       kDifLcCtrlStateTestUnlocked1);
  dut->DutLoadSramElf(openocd_path, ft_individ_elf_path,
                      /*wait_for_done=*/true,
                      /*timeout_ms=*/1000);

  // Transition to mission mode and run FT personalization firmware.
  dut->DutLcTransition(openocd_path, tokens[1].data, kTokenSize128,
                       kDifLcCtrlStateProd);
  dut->DutBootstrap(ft_perso_bin_path);
  dut->DutConsoleWaitForRx("Bootstrap requested.", /*timeout_ms=*/1000);
  dut->DutBootstrap(ft_fw_bundle_path);
  dut->DutTxFtRmaUnlockTokenHash(rma_token_spi_frame.payload,
                                 rma_token_spi_frame.cursor,
                                 /*timeout_ms=*/1000);
  dut->DutTxFtCaSerialNums(ca_serial_numbers_spi_frame.payload,
                           ca_serial_numbers_spi_frame.cursor,
                           /*timeout_ms=*/1000);

  // TODO(timothytrippel): add perso remaining execution steps

  // Close session with PA.
  if (CloseSession(ate_client) != 0) {
    LOG(ERROR) << "CloseSession with PA failed.";
    return -1;
  }
  DestroyClient(ate_client);
  return 0;
}
