// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_
#define OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_certificate_verifier.h>

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "src/pa/proto/pa.grpc.pb.h"

namespace provisioning {
namespace ate {

// Verifies that every certificate in `pem_cert_data` has an ML-DSA public key
// and was signed with an ML-DSA signature algorithm.
grpc::Status VerifyMldsaCertificates(std::string_view pem_cert_data);

// Verifies that `pem_key_data` contains a valid ML-DSA private key.
grpc::Status ValidateMldsaPrivateKey(std::string_view pem_key_data);

// Custom certificate verifier that performs standard hostname verification
// and strictly enforces that peer certificates use ML-DSA public keys and
// signatures.
class MldsaCertificateVerifier
    : public grpc::experimental::ExternalCertificateVerifier {
 public:
  MldsaCertificateVerifier();

  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback,
              grpc::Status* sync_status) override;

  void Cancel(
      grpc::experimental::TlsCustomVerificationCheckRequest* request) override;

 private:
  std::unique_ptr<grpc::experimental::HostNameCertificateVerifier>
      hostname_verifier_;
};

class AteClient {
 public:
  struct Options {
    // Endpoint address in gRPC name-syntax format, including port number. For
    // example: "localhost:5000", "ipv4:127.0.0.1:5000,127.0.0.2:5000", or
    // "ipv6:[::1]:5000,[::1]:5001".
    std::string pa_target;

    // gRPC load balancing policy. If not set, it will be selected by the gRPC
    // library. For example: "round_robin" or "pick_first".
    std::string load_balancing_policy;

    // Set to true to enable mTLS connection. When set to false, the connection
    // is established with insecure credentials.
    bool enable_mtls = false;

    // Set to true to enforce ML-KEM post-quantum key exchange in TLS.
    bool enable_mlkem_tls = false;

    // Set to true to enforce ML-DSA post-quantum certificate verification in
    // TLS.
    bool enable_mldsa_tls = false;

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

  // Constructs an AteClient given a GRPC channel.
  AteClient(std::shared_ptr<grpc::Channel> channel)
      : channel_(channel),
        stub_(pa::ProvisioningApplianceService::NewStub(channel)) {}

  // Constructs an AteClient with a mock stub for testing purposes.
  explicit AteClient(
      std::unique_ptr<pa::ProvisioningApplianceService::StubInterface> stub)
      : channel_(nullptr), stub_(std::move(stub)) {}

  // Forbids copies or assignments of AteClient.
  AteClient(const AteClient&) = delete;
  AteClient& operator=(const AteClient&) = delete;

  // Overload the new and delete operators to allow for usage in a DLL.
  // This ensures that the memory for AteClient objects is allocated and
  // deallocated on the same heap, preventing corruption issues when the DLL
  // and executable have different C++ runtimes.
  void* operator new(size_t size);
  void operator delete(void* ptr);

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

  // Calls the server's GetCaCerts method and returns its reply.
  grpc::Status GetCaCerts(pa::GetCaCertsRequest& request,
                          pa::GetCaCertsResponse* reply);

  // Calls the server's GetOwnerFwBootMessage method and returns its reply.
  grpc::Status GetOwnerFwBootMessage(pa::GetOwnerFwBootMessageRequest& request,
                                     pa::GetOwnerFwBootMessageResponse* reply);

  // Calls the server's RegisterDevice method and returns its reply.
  grpc::Status RegisterDevice(pa::RegistrationRequest& request,
                              pa::RegistrationResponse* reply);

  // SKU name
  std::string Sku;

  // The name of the ATE machine
  std::string ate_id;

 private:
  std::shared_ptr<grpc::Channel> channel_;
  std::unique_ptr<pa::ProvisioningApplianceService::StubInterface> stub_;
  std::string sku_session_token_;
};

// overloads operator<< for AteClient::Options objects printouts
std::ostream& operator<<(std::ostream& os, const AteClient::Options& options);

}  // namespace ate
}  // namespace provisioning
#endif  // OPENTITAN_PROVISIONING_SRC_ATE_ATE_CLIENT_H_
