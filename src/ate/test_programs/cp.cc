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
#include "src/ate/ate_client.h"
#include "src/ate/test_programs/dut_lib/dut_lib.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/version/version.h"

/**
 * DUT configuration flags.
 */
ABSL_FLAG(std::string, fpga, "", "FPGA platform to use.");

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

}  // namespace

int main(int argc, char **argv) {
  // Parse cmd line args.
  absl::FlagsUsageConfig config;
  config.version_string = &VersionFormatted;
  absl::SetFlagsUsageConfig(config);
  absl::ParseCommandLine(argc, argv);
  LOG(INFO) << VersionFormatted();

  // Extract and validate ATE client options.
  AteClient::Options options;
  options.pa_socket = absl::GetFlag(FLAGS_pa_socket);
  options.enable_mtls = absl::GetFlag(FLAGS_enable_mtls);
  if (options.enable_mtls) {
    std::unordered_map<absl::Flag<std::string> *, std::string *> pem_options = {
        {&FLAGS_client_key, &options.pem_private_key},
        {&FLAGS_client_cert, &options.pem_cert_chain},
        {&FLAGS_ca_root_certs, &options.pem_root_certs},
    };

    for (auto opt : pem_options) {
      std::string filename = absl::GetFlag(*opt.first);
      if (filename.empty()) {
        LOG(ERROR) << "--" << absl::GetFlagReflectionHandle(*opt.first).Name()
                   << " not set. This is a required argument when "
                   << " --enable_mtls is set to true." << std::endl;
        return -1;
      }
      auto result = ReadFile(filename);
      if (!result.ok()) {
        LOG(ERROR) << "--" << absl::GetFlagReflectionHandle(*opt.first).Name()
                   << " " << result.status() << std::endl;
        return -1;
      }
      *opt.second = result.value();
    }
  }

  // Instantiate a client.
  auto ate = AteClient::Create(options);

  // Init/Close session.
  grpc::Status status = ate->InitSession(absl::GetFlag(FLAGS_sku),
                                         absl::GetFlag(FLAGS_sku_auth_pw));
  if (!status.ok()) {
    LOG(ERROR) << "InitSession failed with " << status.error_code() << ": "
               << status.error_message() << std::endl;
  }

  // Init session with DUT.
  auto dut = DutLib::Create();
  dut->DutInit(absl::GetFlag(FLAGS_fpga),
               absl::StrCat("third_party/lowrisc/ot_bitstreams/cp_",
                            absl::GetFlag(FLAGS_fpga), ".bit"));

  // TODO(#6): add CP test code here.

  status = ate->CloseSession();
  if (!status.ok()) {
    LOG(ERROR) << "CloseSession failed with " << status.error_code() << ": "
               << status.error_message() << std::endl;
  }

  return 0;
}
