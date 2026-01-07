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

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage_config.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/ate/ate_api.h"
#include "src/version/version.h"

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

}  // namespace

int main(int argc, char **argv) {
  // Parse cmd line args.
  absl::FlagsUsageConfig config;
  absl::SetFlagsUsageConfig(config);
  absl::ParseCommandLine(argc, argv);

  // Set version string.
  config.version_string = &VersionFormatted;
  LOG(INFO) << VersionFormatted();

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
  
  LOG(INFO) << "TLS Connection to PA established successfully.";

  // Close session with PA.
  if (CloseSession(ate_client) != 0) {
    LOG(ERROR) << "CloseSession with PA failed.";
    return -1;
  }
  DestroyClient(ate_client);
  return 0;
}
