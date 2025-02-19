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

// converts the ate output format (CreateKeyAndCertResponse) to secigen input
// format (byte array).
int ConvertResponse(
    pa::CreateKeyAndCertResponse response,  // In: response to be converted
    void *data,                             // Out: converted response
    size_t *max_data_size  // In/Out: maximal/returned buffer size
) {
  DLOG(INFO) << "ConvertResponse";
  int num_of_keys = response.keys_size();
  size_t data_size = 0;  // the accumulated buffer size
  size_t iv_size;        // the iv size (AES_GCM iv)
  blob_t *blob = (blob_t *)data;
  uint32_t alignment_size;
  BlobType keyBlobType;
  pa::EndorsedKey key;

  for (int i = 0; i < num_of_keys; i++) {
    key = response.keys(i);
    // set the blob type according to the key type
    switch (key.wrapped_key().key_format_case()) {
      case crypto::wrap::WrappedKey::kRsaSsaPcks1:
        switch (key.wrapped_key().rsa_ssa_pcks1().modulus_size_in_bits()) {
          case 2048:
            keyBlobType = RSA_2048_KEY_PAYLOAD;
            break;
          case 3072:
            keyBlobType = RSA_3072_KEY_PAYLOAD;
            break;
          case 4096:
            keyBlobType = RSA_4096_KEY_PAYLOAD;
            break;
          default:
            return static_cast<int>(absl::StatusCode::kInternal);
            break;
        }
        break;
      case crypto::wrap::WrappedKey::kEcdsa:
        switch (key.wrapped_key().ecdsa().params().curve()) {
          case crypto::common::EllipticCurveType::ELLIPTIC_CURVE_TYPE_NIST_P384:
            keyBlobType = ECC_384_KEY_PAYLOAD;
            break;
          case crypto::common::EllipticCurveType::ELLIPTIC_CURVE_TYPE_NIST_P256:
            keyBlobType = ECC_256_KEY_PAYLOAD;
            break;
          default:
            return static_cast<int>(absl::StatusCode::kInternal);
            break;
        }
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInternal);
        break;
    }

    iv_size = key.wrapped_key().iv().size();
    // fill even blob's with the key's payload
    blob->type = keyBlobType;
    blob->len = key.wrapped_key().payload().length() + iv_size;
    alignment_size = (sizeof(uint32_t) - ((blob->len) % sizeof(uint32_t))) %
                     sizeof(uint32_t);
    data_size +=
        (sizeof(blob->type) + sizeof(blob->len) + blob->len + alignment_size);
    // verify that the user's allocated buffer size is big enough
    if (data_size > *max_data_size) {
      LOG(ERROR) << "CreateKeyAndCertificate failed- user allocaed buffer is "
                    "too small. allocated "
                 << *max_data_size;
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }
    // copy the iv
    memcpy(&blob->value, key.wrapped_key().iv().c_str(), iv_size);
    // copy the key
    memcpy(&blob->value + iv_size, key.wrapped_key().payload().c_str(),
           (blob->len - iv_size));
    DLOG(INFO) << "blob addrs is " << blob << " ,blob len is " << blob->len
               << " ,blob type is " << blob->type;
    // set the next blob address (and round it up to be alignof(blob_t) bytes)
    blob = reinterpret_cast<blob_t *>(blob->value + blob->len + alignment_size);
    // fill odd blob's with the key's certificate
    blob->type = (BlobType)((int)keyBlobType * 2);
    blob->len = key.cert().blob().length();
    alignment_size = (sizeof(uint32_t) - ((blob->len) % sizeof(uint32_t))) %
                     sizeof(uint32_t);
    data_size +=
        (sizeof(blob->type) + sizeof(blob->len) + blob->len + alignment_size);
    // verify that the user's allocated buffer size is big enough
    if (data_size > *max_data_size) {
      LOG(ERROR) << "CreateKeyAndCertificate failed- user allocaed buffer is "
                    "too small. allocated "
                 << *max_data_size;
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }
    memcpy(&blob->value, key.cert().blob().c_str(), blob->len);
    DLOG(INFO) << "blob addrs is " << blob << " ,blob len is " << blob->len
               << " ,blob type is " << blob->type;
    // set the next blob address (and round it up to be alignof(blob_t) bytes)
    blob = reinterpret_cast<blob_t *>(blob->value + blob->len + alignment_size);
  }

  *max_data_size = data_size;
  DLOG(INFO)
      << "CreateKeyAndCertificate ended successfully. required buffer size is "
      << data_size;
  return 0;
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

DLLEXPORT int CreateKeyAndCertificate(
    ate_client_ptr client,   // In:      pointer to the client
    const char *sku,         // In:      product sku
    void *data,              // Out:     response buffer
    size_t *max_data_size,   // In/Out:  max/returned response buffer size
    const void *pSN = NULL,  // In:      serial number
    const size_t snSize = 0  // In:      serial number size
) {
  DLOG(INFO) << "CreateKeyAndCertificate";
  AteClient *ate = reinterpret_cast<AteClient *>(client);
  pa::CreateKeyAndCertResponse response;

  std::string sn = std::string("");

  if (snSize != 0) {
    sn = std::string((uint8_t *)pSN, (uint8_t *)pSN + snSize);
  }

  // run the service
  auto status = ate->CreateKeyAndCert(sku, sn.data(), sn.size(), &response);
  if (!status.ok()) {
    LOG(ERROR) << "CreateKeyAndCert failed with " << status.error_code() << ": "
               << status.error_message();
    return static_cast<int>(status.error_code());
  }

  return ConvertResponse(response, data, max_data_size);
}

DLLEXPORT derive_symmetric_key_response_t *AllocateDeriveSymmetricKeyResponse(
    size_t key_count) {
  if (key_count == 0) {
    return nullptr;
  }
  size_t header_size = sizeof(derive_symmetric_key_response_t);
  size_t keys_array_size = key_count * sizeof(symmetric_key_t);
  size_t total_size = header_size + keys_array_size;
  auto *response = (derive_symmetric_key_response_t *)malloc(total_size);
  if (response == nullptr) {
    return nullptr;
  }
  response->symmetric_key_count = key_count;

  // Set the symmetric_keys pointer to the start of the keys array.
  response->symmetric_keys =
      (symmetric_key_t *)((uint8_t *)response + header_size);

  return response;
}

DLLEXPORT void FreeDeriveSymmetricKeyResponse(
    derive_symmetric_key_response_t *response) {
  if (response != NULL) {
    free(response);
  }
}

DLLEXPORT int DeriveSymmetricKeys(ate_client_ptr client,
                                  const derive_symmetric_key_request_t *request,
                                  derive_symmetric_key_response_t *response) {
  DLOG(INFO) << "DeriveSymmetricKeys";

  if (request == nullptr || response == nullptr) {
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::DeriveSymmetricKeysRequest req;
  req.set_sku(request->sku);
  for (size_t i = 0; i < request->params_count; ++i) {
    auto param = req.add_params();
    auto &req_params = request->params[i];

    switch (req_params.seed) {
      case kSymmetricKeySeedSecurityLow:
        param->set_seed(pa::SymmetricKeySeed::SYMMETRIC_KEY_SEED_LOW_SECURITY);
        break;
      case kSymmetricKeySeedSecurityHigh:
        param->set_seed(pa::SymmetricKeySeed::SYMMETRIC_KEY_SEED_HIGH_SECURITY);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    switch (req_params.type) {
      case kSymmetricKeyTypeRaw:
        param->set_type(pa::SymmetricKeyType::SYMMETRIC_KEY_TYPE_RAW);
        break;
      case kSymmetricKeyTypHashedLcToken:
        param->set_type(
            pa::SymmetricKeyType::SYMMETRIC_KEY_TYPE_HASHED_OT_LC_TOKEN);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    switch (req_params.size) {
      case kSymmetricKeySize128:
        param->set_size(pa::SymmetricKeySize::SYMMETRIC_KEY_SIZE_128_BITS);
        break;
      case kSymmetricKeySize256:
        param->set_size(pa::SymmetricKeySize::SYMMETRIC_KEY_SIZE_256_BITS);
        break;
      default:
        return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    param->set_diversifier(
        std::string(req_params.diversifier,
                    req_params.diversifier + sizeof(req_params.diversifier)));
  }

  pa::DeriveSymmetricKeysResponse resp;
  auto status = ate->DeriveSymmetricKeys(req, &resp);
  if (!status.ok()) {
    LOG(ERROR) << "DeriveSymmetricKeys failed with " << status.error_code()
               << ": " << status.error_message();
    return static_cast<int>(status.error_code());
  }

  if (resp.keys_size() == 0) {
    return static_cast<int>(absl::StatusCode::kInternal);
  }

  if (response->symmetric_key_count < resp.keys_size()) {
    LOG(ERROR) << "DeriveSymmetricKeys failed- user allocaed buffer is too "
                  "small. allocated: "
               << response->symmetric_key_count;
    return static_cast<int>(absl::StatusCode::kInvalidArgument);
  }

  for (int i = 0; i < resp.keys_size(); i++) {
    auto &key = resp.keys(i);
    auto &resp_key = response->symmetric_keys[i];

    if (key.size() > sizeof(resp_key.key)) {
      LOG(ERROR) << "DeriveSymmetricKeys failed- key size is too big: "
                 << key.size << " bytes. Key index: " << i;
      return static_cast<int>(absl::StatusCode::kInternal);
    }

    resp_key.size = key.size();
    memcpy(resp_key.key, key.c_str(), sizeof(resp_key.key));
  }
  return 0;
}
