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
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/version/version.h"

ABSL_FLAG(std::string, pa_socket, "",
          "host:port of the target provisioning appliance server.");
ABSL_FLAG(bool, enable_mtls, false, "Enable mTLS secure channel.");
ABSL_FLAG(std::string, client_key, "",
          "File path to the PEM encoding of the client's private key.");
ABSL_FLAG(std::string, client_cert, "",
          "File path to the PEM encoding of the  client's certificate chain.");
ABSL_FLAG(std::string, ca_root_certs, "",
          "File path to the PEM encoding of the server root certificates.");

namespace {
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using pa::CreateKeyAndCertRequest;
using pa::CreateKeyAndCertResponse;
using pa::ProvisioningApplianceService;
using provisioning::VersionFormatted;
using provisioning::ate::AteClient;

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
  absl::FlagsUsageConfig config;
  config.version_string = &VersionFormatted;
  absl::SetFlagsUsageConfig(config);

  absl::ParseCommandLine(argc, argv);
  LOG(INFO) << VersionFormatted();

  AteClient::Options options;
  options.enable_mtls = absl::GetFlag(FLAGS_enable_mtls);
  options.pa_socket = absl::GetFlag(FLAGS_pa_socket);
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

  // Call the service method.
  CreateKeyAndCertResponse response;
  uint8_t serial[] = {1, 2, 3, 4, 10, 100};
  grpc::Status status =
      ate->CreateKeyAndCert("tpm_1", serial, sizeof(serial), &response);

  if (status.ok()) {
    LOG(INFO) << "CreateKeyAndCert returned " << response.DebugString();
  } else {
    LOG(ERROR) << "CreateKeyAndCert failed with " << status.error_code() << ": "
               << status.error_message() << std::endl;
  }

  return 0;
}
