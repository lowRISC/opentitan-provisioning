// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_client.h"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>

#include <iostream>
#include <memory>
#include <string>

#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/transport/service_credentials.h"

namespace provisioning {
namespace ate {
namespace {
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using pa::CloseSessionRequest;
using pa::CloseSessionResponse;
using pa::CreateKeyAndCertRequest;
using pa::CreateKeyAndCertResponse;
using pa::InitSessionRequest;
using pa::InitSessionResponse;
using pa::ProvisioningApplianceService;
using pa::RegistrationRequest;
using pa::RegistrationResponse;
using provisioning::transport::ServiceCredentials;

// Creates mTLS and per call channel credentials based on configuration
// `options`.
std::shared_ptr<grpc::ChannelCredentials> BuildCredentials(
    const AteClient::Options& options) {
  grpc::SslCredentialsOptions credentials_opts;
  credentials_opts.pem_root_certs = options.pem_root_certs;
  credentials_opts.pem_private_key = options.pem_private_key;
  credentials_opts.pem_cert_chain = options.pem_cert_chain;

  auto call_credentials = grpc::MetadataCredentialsFromPlugin(
      std::unique_ptr<grpc::MetadataCredentialsPlugin>(
          new ServiceCredentials(options.sku_tokens)));

  return grpc::CompositeChannelCredentials(
      grpc::SslCredentials(credentials_opts), call_credentials);
}
}  // namespace

// Instantiates a client
std::unique_ptr<AteClient> AteClient::Create(AteClient::Options options) {
  LOG(INFO) << "debug info: In AteClient::Create"
            << " AteClient.options: " << options;

  // establish a grpc channel between the client (test program) and the targeted
  // provisioning appliance server:
  // 1. set the grpc channel properties (insecured by default, authenticated and
  // encrypted if specified in options.enable_mtls parameter)
  auto credentials = grpc::InsecureChannelCredentials();
  if (options.enable_mtls) {
    credentials = BuildCredentials(options);
  }
  // 2. create the grpc channel between the client and the targeted server
  auto ate = absl::make_unique<AteClient>(ProvisioningApplianceService::NewStub(
      grpc::CreateChannel(options.pa_socket, credentials)));

  return ate;
}

Status AteClient::InitSession(const std::string& sku,
                              const std::string& sku_auth) {
  LOG(INFO) << "debug info: In AteClient::InitSession"
            << " sku is " << sku;
  Status result;
  Sku = sku;

  InitSessionRequest request;
  request.set_sku(sku);
  request.set_sku_auth(sku_auth);

  InitSessionResponse response;
  ClientContext context;

  result = stub_->InitSession(&context, request, &response);
  if (!result.ok()) {
    return result;
  }
  sku_session_token_ = response.sku_session_token();
  return Status::OK;
}

Status AteClient::CloseSession() {
  LOG(INFO) << "debug info: In AteClient::CloseSession";
  Status result;
  CloseSessionRequest request;
  CloseSessionResponse response;
  ClientContext context;

  result = stub_->CloseSession(&context, request, &response);
  if (!result.ok()) {
    return result;
  }
  return Status::OK;
}

Status AteClient::CreateKeyAndCert(const std::string& sku,
                                   const void* serial_number,
                                   const size_t serial_number_size,
                                   CreateKeyAndCertResponse* reply) {
  LOG(INFO) << "debug info: In AteClient::CreateKeyAndCert";

  // Data we are sending to the server.
  CreateKeyAndCertRequest request;
  request.set_sku(sku);

  if (serial_number_size != 0 && serial_number != NULL) {
    request.set_serial_number(
        (std::string((uint8_t*)serial_number,
                     (uint8_t*)serial_number + serial_number_size)));
  }

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's CreateKeyAndCert method.
  return stub_->CreateKeyAndCert(&context, request, reply);
}

Status AteClient::SendDeviceRegistrationPayload(RegistrationRequest& request,
                                                RegistrationResponse* reply) {
  LOG(INFO) << "debug info: In AteClient::SendDeviceRegistrationPayload";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's SendDeviceRegistrationPayload method.
  return stub_->SendDeviceRegistrationPayload(&context, request, reply);
}

// overloads operator<< for AteClient::Options objects printouts
std::ostream& operator<<(std::ostream& os, const AteClient::Options& options) {
  // write obj to stream
  os << std::endl << "options.pa_socket = " << options.pa_socket << std::endl;
  os << "options.enable_mtls = " << options.enable_mtls << std::endl;
  os << "options.pem_cert_chain = " << options.pem_cert_chain << std::endl;
  os << "options.pem_private_key = " << options.pem_private_key << std::endl;
  os << "options.pem_root_certs = " << options.pem_root_certs << std::endl;
  return os;
}

}  // namespace ate
}  // namespace provisioning
