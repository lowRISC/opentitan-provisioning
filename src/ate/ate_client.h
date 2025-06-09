// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_

#include <grpcpp/grpcpp.h>

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "src/pa/proto/pa.grpc.pb.h"

namespace provisioning {
namespace ate {

class AteClient {
 public:
  struct Options {
    // Endpoint address in IP or DNS format including port number. For example:
    // "localhost:5000".
    std::string pa_socket;

    // Set to true to enable mTLS connection. When set to false, the connection
    // is established with insecure credentials.
    bool enable_mtls;

    // Client certificate in PEM format. Required when `enable_mtls` set to
    // true.
    std::string pem_cert_chain;

    // Client secret key in PEM format. Required when `enable_mtls` set to true.
    std::string pem_private_key;

    // Server root certificates in PEM format. Required when `enable_mtls` set
    // to true.
    std::string pem_root_certs;

    // SKU authentication tokens. These tokens are considered secrets and are
    // used to perform authentication at the client gRPC call level.
    std::vector<std::string> sku_tokens;
  };

  // Constructs an AteClient given a GRPC stub.
  AteClient(
      std::unique_ptr<pa::ProvisioningApplianceService::StubInterface> stub)
      : stub_(std::move(stub)) {}

  // Forbids copies or assignments of AteClient.
  AteClient(const AteClient&) = delete;
  AteClient& operator=(const AteClient&) = delete;

  // Creates an AteClient. See configuration `Options` for more details.
  static std::unique_ptr<AteClient> Create(Options options);

  // Calls the server's InitSession method and returns its reply.
  grpc::Status InitSession(const std::string& sku, const std::string& sku_auth);

  // Calls the server's CloseSession method and returns its reply.
  grpc::Status CloseSession();

  // Calls the server's EndorseCerts method and returns its reply.
  grpc::Status EndorseCerts(pa::EndorseCertsRequest& request,
                            pa::EndorseCertsResponse* reply);

  // Calls the server's DeriveTokens method and returns its reply.
  grpc::Status DeriveTokens(pa::DeriveTokensRequest& request,
                            pa::DeriveTokensResponse* reply);

  // Calls the server's GetCaSubjectKeys method and returns its reply.
  grpc::Status GetCaSubjectKeys(pa::GetCaSubjectKeysRequest& request,
                                pa::GetCaSubjectKeysResponse* reply);

  // Calls the server's RegisterDevice method and returns its reply.
  grpc::Status RegisterDevice(pa::RegistrationRequest& request,
                              pa::RegistrationResponse* reply);

  // SKU name
  std::string Sku;

  // The name of the ATE machine
  std::string ate_id;

 private:
  std::unique_ptr<pa::ProvisioningApplianceService::StubInterface> stub_;
  std::string sku_session_token_;
};

// overloads operator<< for AteClient::Options objects printouts
std::ostream& operator<<(std::ostream& os, const AteClient::Options& options);

}  // namespace ate
}  // namespace provisioning
#endif  // OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_
