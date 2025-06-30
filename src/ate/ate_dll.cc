// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <google/protobuf/util/json_util.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <unordered_map>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "src/ate/ate_api.h"
#include "src/ate/ate_client.h"
#include "src/ate/proto/dut_commands.pb.h"
#include "src/pa/proto/pa.grpc.pb.h"
#include "src/proto/crypto/common.pb.h"
#include "src/proto/crypto/ecdsa.pb.h"
#include "src/proto/device_id.pb.h"

namespace {
using provisioning::ate::AteClient;
using namespace provisioning::ate;
}  // namespace

/**
 * Check the ate_api.h device_life_cycle_t enum values match those in the
 * device_id.proto enum.
 */
static_assert(kDeviceLifeCycleUnspecified ==
                  static_cast<uint32_t>(
                      ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_UNSPECIFIED),
              "LC state enum must match proto enum (Unspecified)");
static_assert(
    kDeviceLifeCycleRaw ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_RAW),
    "LC state enum must match proto enum (Raw)");
static_assert(kDeviceLifeCycleTestLocked ==
                  static_cast<uint32_t>(
                      ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_TEST_LOCKED),
              "LC state enum must match proto enum (TestLocked)");
static_assert(kDeviceLifeCycleTestUnlocked ==
                  static_cast<uint32_t>(
                      ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_TEST_UNLOCKED),
              "LC state enum must match proto enum (TestUnlocked)");
static_assert(
    kDeviceLifeCycleDev ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_DEV),
    "LC state enum must match proto enum (Dev)");
static_assert(
    kDeviceLifeCycleProd ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_PROD),
    "LC state enum must match proto enum (Prod)");
static_assert(
    kDeviceLifeCycleProdEnd ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_PROD_END),
    "LC state enum must match proto enum (ProdEnd)");
static_assert(
    kDeviceLifeCycleRma ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_RMA),
    "LC state enum must match proto enum (Rma)");
static_assert(
    kDeviceLifeCycleScrap ==
        static_cast<uint32_t>(ot::DeviceLifeCycle::DEVICE_LIFE_CYCLE_SCRAP),
    "LC state enum must match proto enum (Scrap)");

std::string extractDNSNameFromCert(const char *certPath) {
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

DLLEXPORT int CreateClient(
    ate_client_ptr *client,    // Out: the created client instance
    client_options_t *options  // In: secure channel attributes
) {
  DLOG(INFO) << "CreateClient";
  AteClient::Options o;

  // convert from ate_client_ptr to AteClient::Options
  o.enable_mtls = options->enable_mtls;
  o.pa_target = options->pa_target;
  if (options->load_balancing_policy != nullptr) {
    o.load_balancing_policy = options->load_balancing_policy;
  }
  if (o.enable_mtls) {
    // Load the PEM data from the pointed files
    absl::Status s =
        LoadPEMResources(&o, options->pem_private_key, options->pem_cert_chain,
                         options->pem_root_certs);
    if (!s.ok()) {
      LOG(ERROR) << "Failed to load needed PEM resources";
      return static_cast<int>(s.code());
    }
  }

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
  *client = reinterpret_cast<ate_client_ptr>(ate.release());

  LOG(INFO) << "debug info: returned from CreateClient with ate = " << *client;
  return 0;
}

DLLEXPORT void DestroyClient(ate_client_ptr client) {
  DLOG(INFO) << "DestroyClient";
  if (client != nullptr) {
    AteClient *ate = reinterpret_cast<AteClient *>(client);
    delete ate;
  } else {
    LOG(WARNING) << "DestroyClient called with a null client pointer";
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
      LOG(ERROR) << "DeriveTokens failed- token size is too big: "
                 << token.size() << " bytes. token index: " << i;
      return static_cast<int>(absl::StatusCode::kInternal);
    }

    resp_token.size = token.size();
    memcpy(resp_token.data, token.data(), resp_token.size);

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
        LOG(ERROR) << "DeriveTokens failed - seed size is too big: " << s.size()
                   << " bytes. Seed index: " << i;
        return static_cast<int>(absl::StatusCode::kInternal);
      }

      seed.size = s.size();
      memcpy(seed.seed, s.data(), seed.size);
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
    param->set_diversifier(req_params.diversifier,
                           sizeof(req_params.diversifier));
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
    param->set_diversifier(req_params.diversifier,
                           sizeof(req_params.diversifier));

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

DLLEXPORT int GetCaSubjectKeys(ate_client_ptr client, const char *sku,
                               size_t count, const char **labels,
                               ca_subject_key_t *key_ids) {
  DLOG(INFO) << "GetCaSubjectKeys";

  if (sku == nullptr || labels == nullptr || count == 0 || key_ids == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  pa::GetCaSubjectKeysRequest req;
  req.set_sku(sku);
  for (size_t i = 0; i < count; ++i) {
    req.add_cert_labels(labels[i]);
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::GetCaSubjectKeysResponse resp;
  auto status = ate->GetCaSubjectKeys(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "GetCaSubjectKeys failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }

  for (size_t i = 0; i < count; ++i) {
    memcpy(key_ids[i].data, resp.key_ids(i).data(), kCaSubjectKeySize);
  }

  return 0;
}

DLLEXPORT int EndorseCerts(ate_client_ptr client, const char *sku,
                           const diversifier_bytes_t *diversifier,
                           const endorse_cert_signature_t *signature,
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
    if (req_params.tbs_size > sizeof(req_params.tbs)) {
      LOG(ERROR) << "EndorseCerts failed - TBS size is too big: "
                 << req_params.tbs_size << " bytes.";
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    bundle->set_tbs(req_params.tbs, req_params.tbs_size);

    auto signing_params = bundle->mutable_key_params();

    // Signing key label.
    if (req_params.key_label_size > kCertificateKeyLabelMaxSize) {
      LOG(ERROR) << "EndorseCerts failed - key label size is too big: "
                 << req_params.key_label_size << " bytes.";
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }
    std::string cert_label(req_params.key_label, req_params.key_label_size);
    signing_params->set_key_label(cert_label);

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

  req.set_diversifier(diversifier->raw, kDiversificationStringSize);
  req.set_signature(signature->raw, kWasHmacSignatureSize);

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

    if (c.cert().blob().size() > sizeof(resp_cert.cert)) {
      LOG(ERROR) << "EndorseCerts failed- certificate size is too big: "
                 << c.cert().blob().size() << " bytes. Certificate index: " << i
                 << ", expected max size: " << sizeof(resp_cert.cert);
      return static_cast<int>(absl::StatusCode::kInternal);
    }

    // Set the cert type.
    // Only signing of X.509 certificates is supported at this time.
    resp_cert.type = kCertTypeX509;

    // Set the cert size.
    resp_cert.cert_size = c.cert().blob().size();
    memcpy(resp_cert.cert, c.cert().blob().data(), c.cert().blob().size());

    if (c.key_label().size() > kCertificateKeyLabelMaxSize) {
      LOG(ERROR) << "EndorseCerts failed - key label size is too big: "
                 << c.key_label().size() << " bytes. Certificate index: " << i
                 << ", expected max size: " << kCertificateKeyLabelMaxSize;
      return static_cast<int>(absl::StatusCode::kInternal);
    }
    resp_cert.key_label_size = c.key_label().size();
    memcpy(resp_cert.key_label, c.key_label().data(), c.key_label().size());
  }
  return 0;
}

DLLEXPORT int GetOwnerFwBootMessage(ate_client_ptr client, const char *sku,
                                    char *boot_msg, size_t boot_msg_size) {
  DLOG(INFO) << "GetOwnerFwBootMessage";

  if (sku == nullptr || boot_msg == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  pa::GetOwnerFwBootMessageRequest req;
  req.set_sku(sku);

  AteClient *ate = reinterpret_cast<AteClient *>(client);
  pa::GetOwnerFwBootMessageResponse resp;
  auto status = ate->GetOwnerFwBootMessage(req, &resp);

  if (!status.ok()) {
    LOG(ERROR) << "GetOwnerFwBootMessage failed with " << status.error_code()
               << ": " << status.error_message();
    return static_cast<int>(status.error_code());
  }

  if (resp.boot_message().size() + 1 > boot_msg_size) {
    LOG(ERROR) << "GetOwnerFwBootMessage failed due to insufficient output "
                  "string size";
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  memcpy(boot_msg, resp.boot_message().c_str(), resp.boot_message().size());
  boot_msg[resp.boot_message().size()] = '\0';

  return 0;
}

// Get the current time in milliseconds.
uint64_t getMilliseconds(void) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::high_resolution_clock::now().time_since_epoch())
      .count();
}

DLLEXPORT int RegisterDevice(
    ate_client_ptr client, const char *sku, const device_id_t *device_id,
    device_life_cycle_t device_life_cycle, const metadata_t *metadata,
    const wrapped_seed_t *wrapped_rma_unlock_token_seed,
    const perso_blob_t *perso_blob_for_registry,
    const sha256_hash_t *perso_fw_hash,
    const sha256_hash_t *hash_of_all_certs) {
  DLOG(INFO) << "RegisterDevice";

  if (sku == nullptr || device_id == nullptr || metadata == nullptr ||
      perso_blob_for_registry == nullptr || perso_fw_hash == nullptr) {
    LOG(ERROR) << "RegisterDevice failed - invalid pointer arg.";
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }
  const std::set<device_life_cycle_t> kMissionModeLcStates = {
      kDeviceLifeCycleDev, kDeviceLifeCycleProd, kDeviceLifeCycleProdEnd};
  if (kMissionModeLcStates.count(device_life_cycle) == 0) {
    LOG(ERROR) << "RegisterDevice failed - invalid mission mode LC state.";
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  // Build the RegisterDeviceRequest object.
  pa::RegistrationRequest req;
  auto device_data = req.mutable_device_data();

  // Certs hash type and hash.
  req.set_hash_type(crypto::common::HashType::HASH_TYPE_SHA256);
  req.set_certs_hash(std::string(
      reinterpret_cast<const char *>(hash_of_all_certs->raw), kSha256HashSize));

  // SKU.
  device_data->set_sku(sku);

  // Device ID.
  auto hardware_origin =
      device_data->mutable_device_id()->mutable_hardware_origin();
  hardware_origin->set_silicon_creator_id(static_cast<ot::SiliconCreatorId>(
      device_id->hardware_origin.silicon_creator_id));
  hardware_origin->set_product_id(
      static_cast<ot::ProductId>(device_id->hardware_origin.product_id));
  hardware_origin->set_device_identification_number(
      device_id->hardware_origin.device_identification_number);
  device_data->mutable_device_id()->set_sku_specific(
      std::string(reinterpret_cast<const char *>(device_id->sku_specific),
                  sizeof(device_id->sku_specific)));

  // Device Lifecycle state.
  device_data->set_device_life_cycle(
      static_cast<ot::DeviceLifeCycle>(device_life_cycle));

  // Metadata.
  auto current_time_ms = getMilliseconds();
  device_data->mutable_metadata()->set_registration_state(
      ot::DeviceRegistrationState::DEVICE_REGISTRATION_STATE_PROVISIONED);
  device_data->mutable_metadata()->set_create_time_ms(current_time_ms);
  device_data->mutable_metadata()->set_update_time_ms(current_time_ms);
  device_data->mutable_metadata()->set_ate_id(ate->ate_id);
  device_data->mutable_metadata()->set_ate_raw("");
  device_data->mutable_metadata()->set_year(metadata->year);
  device_data->mutable_metadata()->set_week(metadata->week);
  device_data->mutable_metadata()->set_lot_num(metadata->lot_num);
  device_data->mutable_metadata()->set_wafer_id(metadata->wafer_id);
  device_data->mutable_metadata()->set_x(metadata->x);
  device_data->mutable_metadata()->set_y(metadata->y);

  // Wrapped RMA unlock token seed.
  device_data->set_wrapped_rma_unlock_token(std::string(
      reinterpret_cast<const char *>(wrapped_rma_unlock_token_seed->seed),
      wrapped_rma_unlock_token_seed->size));

  // Perso TLV data.
  device_data->set_perso_tlv_data(
      std::string(reinterpret_cast<const char *>(perso_blob_for_registry->body),
                  perso_blob_for_registry->next_free));
  device_data->set_num_perso_tlv_objects(perso_blob_for_registry->num_objects);

  // Perso firmware SHA256 hash.
  device_data->set_perso_fw_sha256_hash(std::string(
      reinterpret_cast<const char *>(perso_fw_hash->raw), kSha256HashSize));

  // Send the request to the PA.
  pa::RegistrationResponse resp;
  auto status = ate->RegisterDevice(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "RegisterDevice failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }

  return 0;
}
