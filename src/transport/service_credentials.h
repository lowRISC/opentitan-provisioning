// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_TRANSPORT_SERVICE_CREDENTIALS_H_
#define OPENTITAN_PROVISIONING_SRC_TRANSPORT_SERVICE_CREDENTIALS_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>

#include <string>
#include <vector>

namespace provisioning {
namespace transport {

// Class used to provide client call credentials. Credentials are managed at
// the SKU level. A client may present more than one SKU credential if needed.
//
// The credentials require to be exchanged in a secure channel. For production
// use cases, SSL credentials will be used to establish the secure channel
// using an mTLS configuration.
//
// See https://grpc.io/docs/guides/auth/#authentication-api for more details.
class ServiceCredentials : public grpc::MetadataCredentialsPlugin {
 public:
  explicit ServiceCredentials(const std::vector<std::string>& sku_tokens);
  ~ServiceCredentials() override {}

  bool IsBlocking() const override { return false; }
  const char* GetType() const override { return "OpenTitanAuthToken"; }
  std::string DebugString() override { return "OpenTitanAuthToken"; }

  grpc::Status GetMetadata(
      grpc::string_ref service_url, grpc::string_ref method_name,
      const grpc::AuthContext& channel_auth_context,
      std::multimap<grpc::string, grpc::string>* metadata) override;

 private:
  std::vector<std::string> sku_tokens_;
};

}  // namespace transport
}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_TRANSPORT_SERVICE_CREDENTIALS_H_
