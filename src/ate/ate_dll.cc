// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <iostream>
#include <unordered_map>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/ate/ate_api.h"
#include "src/ate/ate_client.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/proto/crypto/common.pb.h"
#include "src/proto/crypto/ecdsa.pb.h"

namespace {
using provisioning::ate::AteClient;
using namespace provisioning::ate;
}  // namespace

std::string extractDNSNameFromCert(const char *certPath) {
  DLOG(INFO) << "extractDNSNameFromCert";
  FILE *certFile = fopen(certPath, "r");
  if (!certFile) {
    LOG(ERROR) << "Failed to open certificate file";
    return "";
  }

  X509 *cert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
  fclose(certFile);

  if (!cert) {
    LOG(ERROR) << "Failed to parse certificate";
    return "";
  }

  // check that extension exist
  STACK_OF(GENERAL_NAME) *sanExtension = static_cast<STACK_OF(GENERAL_NAME) *>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if (!sanExtension) {
    LOG(ERROR) << "Subject Alternative Name extension not found";
    X509_free(cert);
    return "";
  }

  int numEntries = sk_GENERAL_NAME_num(sanExtension);

  std::string dnsName = "";

  // search for DNS name
  for (int i = 0; i < numEntries; ++i) {
    GENERAL_NAME *sanEntry = sk_GENERAL_NAME_value(sanExtension, i);
    if (sanEntry->type == GEN_DNS) {
      ASN1_STRING *dnsNameAsn1 = sanEntry->d.dNSName;
      dnsName = std::string(
          reinterpret_cast<const char *>(ASN1_STRING_get0_data(dnsNameAsn1)),
          ASN1_STRING_length(dnsNameAsn1));
      break;
    }
  }

  sk_GENERAL_NAME_pop_free(sanExtension, GENERAL_NAME_free);
  X509_free(cert);

  return dnsName;
}

int WriteFile(const std::string &filename, std::string input_str) {
  std::ofstream file_stream(filename, std::ios::app | std::ios_base::out);
  if (!file_stream.is_open()) {
    // Failed open
    return static_cast<int>(absl::StatusCode::kInternal);
  }
  file_stream << input_str << std::endl;
  return 0;
}

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

// Loads the PEM data from the files into 'options'
absl::Status LoadPEMResources(AteClient::Options *options,
                              const std::string &pem_private_key_file,
                              const std::string &pem_cert_chain_file,
                              const std::string &pem_root_certs_file) {
  auto data = ReadFile(pem_private_key_file);
  if (!data.ok()) {
    LOG(ERROR) << "Could not read the pem_private_key file: " << data.status();
    return data.status();
  }
  options->pem_private_key = data.value();

  data = ReadFile(pem_cert_chain_file);
  if (!data.ok()) {
    LOG(ERROR) << "Could not read the pem_private_key file: " << data.status();
    return data.status();
  }
  options->pem_cert_chain = data.value();

  data = ReadFile(pem_root_certs_file);
  if (!data.ok()) {
    LOG(ERROR) << "Could not read the pem_private_key file: " << data.status();
    return data.status();
  }
  options->pem_root_certs = data.value();
  return absl::OkStatus();
}

static ate_client_ptr ate_client = nullptr;

DLLEXPORT void CreateClient(
    ate_client_ptr *client,    // Out: the created client instance
    client_options_t *options  // In: secure channel attributes
) {
  DLOG(INFO) << "CreateClient";
  AteClient::Options o;

  // convert from ate_client_ptr to AteClient::Options
  o.enable_mtls = options->enable_mtls;
  o.pa_socket = options->pa_socket;
  if (o.enable_mtls) {
    // Load the PEM data from the pointed files
    absl::Status s =
        LoadPEMResources(&o, options->pem_private_key, options->pem_cert_chain,
                         options->pem_root_certs);
    if (!s.ok()) {
      LOG(ERROR) << "Failed to load needed PEM resources";
    }
  }

  if (ate_client == nullptr) {
    // created client instance
    auto ate = AteClient::Create(o);

    // Clear the ATE name
    ate->ate_id = "";
    if (o.enable_mtls) {
      ate->ate_id = extractDNSNameFromCert(options->pem_cert_chain);
    }

    // In case there is no name to be found, then set the ATE ID to its default
    // value
    if (ate->ate_id.empty()) {
      ate->ate_id = "No ATE ID";
    }

    // Release the managed pointer to a raw pointer and cast to the
    // C out type.
    ate_client = reinterpret_cast<ate_client_ptr>(ate.release());
  }
  *client = ate_client;

  LOG(INFO) << "debug info: returned from CreateClient with ate = " << *client;
}

DLLEXPORT void DestroyClient(ate_client_ptr client) {
  DLOG(INFO) << "DestroyClient";
  if (ate_client != nullptr) {
    AteClient *ate = reinterpret_cast<AteClient *>(client);
    delete ate;
    ate_client = nullptr;
  }
}

DLLEXPORT int InitSession(ate_client_ptr client, const char *sku,
                          const char *sku_auth) {
  DLOG(INFO) << "InitSession";
  AteClient *ate = reinterpret_cast<AteClient *>(client);

  // run the service
  auto status = ate->InitSession(sku, sku_auth);
  if (!status.ok()) {
    LOG(ERROR) << "InitSession failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }
  return 0;
}

DLLEXPORT int CloseSession(ate_client_ptr client) {
  DLOG(INFO) << "CloseSession";
  AteClient *ate = reinterpret_cast<AteClient *>(client);

  // run the service
  auto status = ate->CloseSession();
  if (!status.ok()) {
    LOG(ERROR) << "CloseSession failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }
  return 0;
}

namespace {

// Convert `token_seed_t` to `TokenSeed`.
int TokenSetSeedConfig(token_seed_t seed_kind, pa::TokenParams *param) {
  switch (seed_kind) {
    case kTokenSeedSecurityLow:
      param->set_seed(pa::TokenSeed::TOKEN_SEED_LOW_SECURITY);
      break;
    case kTokenSeedSecurityHigh:
      param->set_seed(pa::TokenSeed::TOKEN_SEED_HIGH_SECURITY);
      break;
    default:
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }
  return 0;
}

// Convert `token_type_t` to `TokenType`.
int TokenSetType(token_type_t token_type, pa::TokenParams *param) {
  switch (token_type) {
    case kTokenTypeRaw:
      param->set_type(pa::TokenType::TOKEN_TYPE_RAW);
      break;
    case kTokenTypeHashedLcToken:
      param->set_type(pa::TokenType::TOKEN_TYPE_HASHED_OT_LC_TOKEN);
      break;
    default:
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }
  return 0;
}

// Convert `token_size_t` to `TokenSize`.
int TokenSetSize(token_size_t token_size, pa::TokenParams *param) {
  switch (token_size) {
    case kTokenSize128:
      param->set_size(pa::TokenSize::TOKEN_SIZE_128_BITS);
      break;
    case kTokenSize256:
      param->set_size(pa::TokenSize::TOKEN_SIZE_256_BITS);
      break;
    default:
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }
  return 0;
}

// Copy the tokens and seeds from the response to the output buffers.
int TokensCopy(size_t count, const pa::DeriveTokensResponse &resp,
               token_t *tokens, wrapped_seed_t *seeds) {
  if (tokens == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  if (resp.tokens_size() == 0) {
    return static_cast<int>(absl::StatusCode::kInternal);
  }

  if (count < resp.tokens_size()) {
    LOG(ERROR) << "DeriveTokens failed - user allocaed buffer is too "
                  "small. allocated: "
               << count << " , required: " << resp.tokens_size();
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  for (int i = 0; i < resp.tokens_size(); i++) {
    auto &sk = resp.tokens(i);
    auto &resp_token = tokens[i];
    auto token = sk.token();

    if (token.size() > sizeof(resp_token.data)) {
      LOG(ERROR) << "DeriveTokens failed- token size is too big: " << token.size
                 << " bytes. token index: " << i;
      return static_cast<int>(absl::StatusCode::kInternal);
    }

    resp_token.size = token.size();
    memcpy(resp_token.data, token.c_str(), sizeof(resp_token.data));

    if (seeds != nullptr) {
      auto &s = sk.wrapped_seed();
      wrapped_seed_t &seed = seeds[i];

      if (s.size() == 0) {
        LOG(ERROR) << "DeriveTokens failed - seed size is 0 bytes. Seed "
                      "index: "
                   << i;
        return static_cast<int>(absl::StatusCode::kInternal);
      }

      if (s.size() > sizeof(seed.seed)) {
        LOG(ERROR) << "DeriveTokens failed - seed size is too big: " << s.size
                   << " bytes. Seed index: " << i;
        return static_cast<int>(absl::StatusCode::kInternal);
      }

      seed.size = s.size();
      memcpy(seed.seed, s.c_str(), sizeof(seed.seed));
    }
  }
  return 0;
}

}  // namespace

DLLEXPORT int DeriveTokens(ate_client_ptr client, const char *sku, size_t count,
                           const derive_token_params_t *params,
                           token_t *tokens) {
  DLOG(INFO) << "DeriveTokens";

  if (params == nullptr || tokens == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  pa::DeriveTokensRequest req;
  req.set_sku(sku);
  for (size_t i = 0; i < count; ++i) {
    auto param = req.add_params();
    auto &req_params = params[i];
    int result = TokenSetSeedConfig(req_params.seed, param);
    if (result != 0) {
      return result;
    }
    result = TokenSetType(req_params.type, param);
    if (result != 0) {
      return result;
    }
    result = TokenSetSize(req_params.size, param);
    if (result != 0) {
      return result;
    }
    param->set_diversifier(
        std::string(req_params.diversifier,
                    req_params.diversifier + sizeof(req_params.diversifier)));
    param->set_wrap_seed(false);
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::DeriveTokensResponse resp;
  auto status = ate->DeriveTokens(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "DeriveTokens failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }
  return TokensCopy(count, resp, tokens, /*seeds=*/nullptr);
}

DLLEXPORT int GenerateTokens(ate_client_ptr client, const char *sku,
                             size_t count,
                             const generate_token_params_t *params,
                             token_t *tokens, wrapped_seed_t *seeds) {
  DLOG(INFO) << "GenerateTokens";

  if (params == nullptr || tokens == nullptr || seeds == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  pa::DeriveTokensRequest req;
  req.set_sku(sku);
  for (size_t i = 0; i < count; ++i) {
    auto param = req.add_params();
    auto &req_params = params[i];
    int result = TokenSetType(req_params.type, param);
    if (result != 0) {
      return result;
    }
    result = TokenSetSize(req_params.size, param);
    if (result != 0) {
      return result;
    }
    param->set_diversifier(
        std::string(req_params.diversifier,
                    req_params.diversifier + sizeof(req_params.diversifier)));

    // The following parameters are set to request keygen and seed wrapping.
    param->set_seed(pa::TokenSeed::TOKEN_SEED_KEYGEN);
    param->set_wrap_seed(true);
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::DeriveTokensResponse resp;
  auto status = ate->DeriveTokens(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "GenerateTokens failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }

  return TokensCopy(count, resp, tokens, seeds);
}

DLLEXPORT int EndorseCerts(ate_client_ptr client, const char *sku,
                           const size_t cert_count,
                           const endorse_cert_request_t *request,
                           endorse_cert_response_t *certs) {
  DLOG(INFO) << "EndorseCerts";

  if (request == nullptr || certs == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  pa::EndorseCertsRequest req;
  req.set_sku(sku);
  for (size_t i = 0; i < cert_count; ++i) {
    auto bundle = req.add_bundles();
    auto &req_params = request[i];

    // TBS certificate buffer.
    bundle->set_tbs(std::string(req_params.tbs,
                                req_params.tbs + sizeof(req_params.tbs_size)));

    auto signing_params = bundle->mutable_key_params();

    // Signing key label.
    signing_params->set_key_label(req_params.key_label);

    // Only ECDSA keys are supported at this time.
    auto key = signing_params->mutable_ecdsa_params();

    switch (req_params.hash_type) {
      case kHashTypeSha256:
        key->set_hash_type(crypto::common::HashType::HASH_TYPE_SHA256);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    switch (req_params.curve_type) {
      case kCurveTypeP256:
        key->set_curve(
            crypto::common::EllipticCurveType::ELLIPTIC_CURVE_TYPE_NIST_P256);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    switch (req_params.signature_encoding) {
      case kSignatureEncodingDer:
        key->set_encoding(crypto::ecdsa::EcdsaSignatureEncoding::
                              ECDSA_SIGNATURE_ENCODING_DER);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);
  pa::EndorseCertsResponse resp;
  auto status = ate->EndorseCerts(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "EndorseCerts failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }

  if (resp.certs_size() == 0) {
    LOG(ERROR) << "EndorseCerts failed- no certificates were returned";
    return static_cast<int>(absl::StatusCode::kInternal);
  }

  if (cert_count < resp.certs_size()) {
    LOG(ERROR) << "EndorseCerts failed- user allocaed buffer is too small. "
                  "allocated: "
               << cert_count << " , required: " << resp.certs_size();
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  for (int i = 0; i < resp.certs_size(); i++) {
    auto &c = resp.certs(i);
    auto &resp_cert = certs[i];

    if (c.blob().size() > resp_cert.size) {
      LOG(ERROR) << "EndorseCerts failed- certificate size is too big: "
                 << c.blob().size() << " bytes. Certificate index: " << i
                 << ", expected max size: " << resp_cert.size;
      return static_cast<int>(absl::StatusCode::kInternal);
    }

    resp_cert.size = c.blob().size();
    memcpy(resp_cert.cert, c.blob().c_str(), c.blob().size());
  }
  return 0;
}
