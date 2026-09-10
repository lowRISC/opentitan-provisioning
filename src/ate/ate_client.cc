// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "src/ate/ate_client.h"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_certificate_verifier.h>
#include <grpcpp/security/tls_credentials_options.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
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
using pa::DeriveTokensRequest;
using pa::DeriveTokensResponse;
using pa::EndorseCertsRequest;
using pa::EndorseCertsResponse;
using pa::GetCaCertsRequest;
using pa::GetCaCertsResponse;
using pa::GetCaSubjectKeysRequest;
using pa::GetCaSubjectKeysResponse;
using pa::GetOwnerFwBootMessageRequest;
using pa::GetOwnerFwBootMessageResponse;
using pa::InitSessionRequest;
using pa::InitSessionResponse;
using pa::ProvisioningApplianceService;
using pa::RegistrationRequest;
using pa::RegistrationResponse;
using provisioning::transport::ServiceCredentials;

bool IsMldsaPublicKey(const EVP_PKEY* pkey) {
  if (!pkey) {
    return false;
  }
  int id = EVP_PKEY_id(pkey);
  return id == EVP_PKEY_ML_DSA_44 || id == EVP_PKEY_ML_DSA_65 ||
         id == EVP_PKEY_ML_DSA_87;
}

bool IsMldsaSignatureAlgorithm(int nid) {
  return nid == NID_ML_DSA_44 || nid == NID_ML_DSA_65 || nid == NID_ML_DSA_87;
}

}  // namespace

grpc::Status ValidateMldsaPrivateKey(std::string_view pem_key_data) {
  if (pem_key_data.empty()) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "Private key data is empty");
  }
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(
      pem_key_data.data(), static_cast<int>(pem_key_data.size())));
  if (!bio) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Failed to create BIO for private key");
  }
  bssl::UniquePtr<EVP_PKEY> pkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!pkey) {
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                        "Failed to parse private key");
  }
  if (!IsMldsaPublicKey(pkey.get())) {
    return grpc::Status(
        grpc::StatusCode::INVALID_ARGUMENT,
        absl::StrFormat(
            "Client certificate key is not an MLDSA private key (type: %d)",
            EVP_PKEY_id(pkey.get())));
  }
  return grpc::Status::OK;
}

grpc::Status VerifyMldsaCertificates(std::string_view pem_cert_data) {
  if (pem_cert_data.empty()) {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "no peer certificates provided");
  }
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(
      pem_cert_data.data(), static_cast<int>(pem_cert_data.size())));
  if (!bio) {
    return grpc::Status(grpc::StatusCode::INTERNAL,
                        "Failed to create BIO for certificates");
  }

  std::vector<bssl::UniquePtr<X509>> certs;
  while (true) {
    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
      break;
    }
    certs.emplace_back(cert);
  }

  if (certs.empty()) {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        "failed to parse peer certificates");
  }

  for (size_t i = 0; i < certs.size(); ++i) {
    X509* cert = certs[i].get();
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey) {
      return grpc::Status(
          grpc::StatusCode::UNAUTHENTICATED,
          absl::StrFormat("certificate at index %zu in chain has no public key",
                          i));
    }
    int key_type = EVP_PKEY_id(pkey);
    if (!IsMldsaPublicKey(pkey)) {
      return grpc::Status(
          grpc::StatusCode::UNAUTHENTICATED,
          absl::StrFormat("certificate at index %zu in chain has non-MLDSA "
                          "public key algorithm %d",
                          i, key_type));
    }
    int sig_nid = X509_get_signature_nid(cert);
    if (!IsMldsaSignatureAlgorithm(sig_nid)) {
      return grpc::Status(
          grpc::StatusCode::UNAUTHENTICATED,
          absl::StrFormat("certificate at index %zu in chain has non-MLDSA "
                          "signature algorithm %d",
                          i, sig_nid));
    }
  }

  return grpc::Status::OK;
}

MldsaCertificateVerifier::MldsaCertificateVerifier()
    : hostname_verifier_(
          std::make_unique<grpc::experimental::HostNameCertificateVerifier>()) {
}

bool MldsaCertificateVerifier::Verify(
    grpc::experimental::TlsCustomVerificationCheckRequest* request,
    std::function<void(grpc::Status)> callback, grpc::Status* sync_status) {
  if (request == nullptr) {
    *sync_status = grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "Verification request is null");
    return true;
  }

  // 1. Perform standard hostname verification.
  grpc::Status hn_status;
  hostname_verifier_->Verify(request, nullptr, &hn_status);
  if (!hn_status.ok()) {
    *sync_status = hn_status;
    return true;
  }

  // 2. Enforce ML-DSA algorithm policy across the peer certificate chain.
  grpc::string_ref cert_data = request->peer_cert_full_chain();
  if (cert_data.empty()) {
    cert_data = request->peer_cert();
  }
  if (cert_data.empty()) {
    *sync_status = grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                "no peer certificates provided");
    return true;
  }

  *sync_status = VerifyMldsaCertificates(
      std::string_view(cert_data.data(), cert_data.size()));
  return true;
}

void MldsaCertificateVerifier::Cancel(
    grpc::experimental::TlsCustomVerificationCheckRequest* request) {
  if (hostname_verifier_) {
    hostname_verifier_->Cancel(request);
  }
}

namespace {
// Creates mTLS and per call channel credentials based on configuration
// `options`.
std::shared_ptr<grpc::ChannelCredentials> BuildCredentials(
    const AteClient::Options& options) {
  std::shared_ptr<grpc::ChannelCredentials> channel_creds;

  if (options.enable_mldsa_tls) {
    if (!options.pem_private_key.empty()) {
      grpc::Status status = ValidateMldsaPrivateKey(options.pem_private_key);
      if (!status.ok()) {
        LOG(ERROR) << status.error_message();
        return nullptr;
      }
    }
    if (!options.pem_cert_chain.empty()) {
      grpc::Status status = VerifyMldsaCertificates(options.pem_cert_chain);
      if (!status.ok()) {
        LOG(ERROR) << "Client certificate verification failed: "
                   << status.error_message();
        return nullptr;
      }
    }
    if (!options.pem_root_certs.empty()) {
      grpc::Status status = VerifyMldsaCertificates(options.pem_root_certs);
      if (!status.ok()) {
        LOG(ERROR) << "Root CA certificate verification failed: "
                   << status.error_message();
        return nullptr;
      }
    }
  }

  if (options.enable_mldsa_tls || options.enable_mlkem_tls) {
    grpc::experimental::TlsChannelCredentialsOptions tls_options;

    std::vector<grpc::experimental::IdentityKeyCertPair> identity_pairs;
    if (!options.pem_private_key.empty() && !options.pem_cert_chain.empty()) {
      identity_pairs.push_back(
          {options.pem_private_key, options.pem_cert_chain});
    }

    auto cert_provider =
        std::make_shared<grpc::experimental::StaticDataCertificateProvider>(
            options.pem_root_certs, identity_pairs);
    tls_options.set_certificate_provider(cert_provider);
    tls_options.watch_root_certs();
    if (!identity_pairs.empty()) {
      tls_options.watch_identity_key_cert_pairs();
    }

    tls_options.set_min_tls_version(grpc_tls_version::TLS1_3);

    if (options.enable_mldsa_tls) {
      auto verifier = grpc::experimental::ExternalCertificateVerifier::Create<
          MldsaCertificateVerifier>();
      tls_options.set_certificate_verifier(verifier);
    }

    channel_creds = grpc::experimental::TlsCredentials(tls_options);
  } else {
    grpc::SslCredentialsOptions credentials_opts;
    credentials_opts.pem_root_certs = options.pem_root_certs;
    credentials_opts.pem_private_key = options.pem_private_key;
    credentials_opts.pem_cert_chain = options.pem_cert_chain;
    channel_creds = grpc::SslCredentials(credentials_opts);
  }

  if (!channel_creds) {
    return nullptr;
  }

  auto call_credentials = grpc::MetadataCredentialsFromPlugin(
      std::unique_ptr<grpc::MetadataCredentialsPlugin>(
          new ServiceCredentials(options.sku_tokens)));

  return grpc::CompositeChannelCredentials(channel_creds, call_credentials);
}
}  // namespace

// By explicitly defining the new and delete operators for the AteClient class
// and implementing them in the same compilation unit (the DLL), we ensure
// that the memory for AteClient objects is allocated and deallocated on the
// same heap.
//
// On Windows, a DLL and the executable that loads it can have different C++
// runtime heaps. If an object is allocated on one heap (e.g., by a call
// from the .exe that results in a `new` inside the DLL) and deallocated on
// another (e.g., by a `delete` call in the DLL that might resolve to the
// .exe's runtime), it can lead to heap corruption and access violation
// errors.
//
// These overloads ensure that `new AteClient` and `delete AteClient` always
// use the memory management functions from the C++ runtime linked with this
// DLL, preventing such issues.
void* AteClient::operator new(size_t size) {
  // Forward to the global new operator from the DLL's runtime.
  return ::operator new(size);
}

void AteClient::operator delete(void* ptr) {
  // Forward to the global delete operator from the DLL's runtime.
  ::operator delete(ptr);
}

// Instantiates a client
std::unique_ptr<AteClient> AteClient::Create(AteClient::Options options) {
  // establish a grpc channel between the client (test program) and the targeted
  // provisioning appliance server:
  // 1. set the grpc channel properties (insecured by default, authenticated and
  // encrypted if specified in options.enable_mtls parameter)
  auto credentials = grpc::InsecureChannelCredentials();
  if (options.enable_mtls) {
    credentials = BuildCredentials(options);
    if (!credentials) {
      LOG(ERROR) << "Failed to build channel credentials";
      return nullptr;
    }
  }
  // 2. create the grpc channel between the client and the targeted server
  grpc::ChannelArguments args;
  if (!options.load_balancing_policy.empty()) {
    args.SetLoadBalancingPolicyName(options.load_balancing_policy);
  }
  auto channel =
      grpc::CreateCustomChannel(options.pa_target, credentials, args);
  auto ate = absl::make_unique<AteClient>(channel);

  return ate;
}

Status AteClient::InitSession(const std::string& sku,
                              const std::string& sku_auth) {
  LOG(INFO) << "AteClient::InitSession, sku: " << sku;
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
  LOG(INFO) << "AteClient::CloseSession";
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

Status AteClient::EndorseCerts(EndorseCertsRequest& request,
                               EndorseCertsResponse* reply) {
  LOG(INFO) << "AteClient::EndorseCerts";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's EndorseCerts method.
  return stub_->EndorseCerts(&context, request, reply);
}

Status AteClient::DeriveTokens(DeriveTokensRequest& request,
                               DeriveTokensResponse* reply) {
  LOG(INFO) << "AteClient::DeriveTokens";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's DeriveTokens method.
  return stub_->DeriveTokens(&context, request, reply);
}

Status AteClient::GetCaSubjectKeys(GetCaSubjectKeysRequest& request,
                                   GetCaSubjectKeysResponse* reply) {
  LOG(INFO) << "AteClient::GetCaSubjectKeys";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's DeriveTokens method.
  return stub_->GetCaSubjectKeys(&context, request, reply);
}

Status AteClient::GetCaCerts(GetCaCertsRequest& request,
                             GetCaCertsResponse* reply) {
  LOG(INFO) << "AteClient::GetCaCerts";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's DeriveTokens method.
  return stub_->GetCaCerts(&context, request, reply);
}

Status AteClient::GetOwnerFwBootMessage(GetOwnerFwBootMessageRequest& request,
                                        GetOwnerFwBootMessageResponse* reply) {
  LOG(INFO) << "AteClient::GetOwnerFwBootMessage";
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);
  return stub_->GetOwnerFwBootMessage(&context, request, reply);
}

Status AteClient::RegisterDevice(RegistrationRequest& request,
                                 RegistrationResponse* reply) {
  LOG(INFO) << "AteClient::RegisterDevice";

  // Context for the client (It could be used to convey extra information to
  // the server and/or tweak certain RPC behaviors).
  ClientContext context;
  context.AddMetadata("authorization", sku_session_token_);

  // The actual RPC - call the server's RegisterDevice method.
  return stub_->RegisterDevice(&context, request, reply);
}

// overloads operator<< for AteClient::Options objects printouts
std::ostream& operator<<(std::ostream& os, const AteClient::Options& options) {
  // write obj to stream
  os << std::endl << "options.pa_target = " << options.pa_target << std::endl;
  os << "options.load_balancing_policy = " << options.load_balancing_policy
     << std::endl;
  os << "options.enable_mtls = " << options.enable_mtls << std::endl;
  os << "options.enable_mlkem_tls = " << options.enable_mlkem_tls << std::endl;
  os << "options.enable_mldsa_tls = " << options.enable_mldsa_tls << std::endl;
  os << "options.pem_cert_chain = " << options.pem_cert_chain << std::endl;
  os << "options.pem_private_key = " << options.pem_private_key << std::endl;
  os << "options.pem_root_certs = " << options.pem_root_certs << std::endl;
  return os;
}

}  // namespace ate
}  // namespace provisioning
