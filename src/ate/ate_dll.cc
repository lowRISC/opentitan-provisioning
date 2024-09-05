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

#define ASCII(val) (((val) > 9) ? (((val)-0xA) + 'A') : ((val) + '0'))

std::string extractDNSNameFromCert(const char *certPath) {
  LOG(INFO) << "debug info: In call extractDNSNameFromCert";
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
  LOG(INFO) << "debug info: In dll ConvertResponse";
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
    LOG(INFO) << "debug info: blob addrs is " << blob << " ,blob len is "
              << blob->len << " ,blob type is " << blob->type;
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
    LOG(INFO) << "debug info: blob addrs is " << blob << " ,blob len is "
              << blob->len << " ,blob type is " << blob->type;
    // set the next blob address (and round it up to be alignof(blob_t) bytes)
    blob = reinterpret_cast<blob_t *>(blob->value + blob->len + alignment_size);
  }

  *max_data_size = data_size;
  LOG(INFO) << "debug info: CreateKeyAndCertificate ended successfully. "
               "required buffer size is "
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

  // TODO: why I fail on the next syntax? on "error: could not convert...from
  // '<brace-enclosed initializer list>' to 'std::unordered_map<const
  // std::__cxx11::basic_string<char>&, std::__cxx11::basic_string<char>*>"
  /*
    // create pairs of pem files names and pem files data
    std::unordered_map<const std::string&, std::string*> pem_options = {
        {pem_private_key_file, options->pem_private_key},
        {pem_cert_chain_file, options->pem_cert_chain},
        {pem_root_certs_file, options->pem_root_certs},
    };

    // for each pair, read the 'filename' content (a PEM data)
    for (auto opt : pem_options) {
      // get the pem file name
      std::string filename = *opt.first;
      // get the pem file data
      auto data = ReadFile(filename);
      if (!data.ok()) {
        LOG(ERROR) << "Error: reading from pem file " << *opt.first
                    << " failed on the following error:" << data.status();
      }
      *opt.second = data.value();
    }
  */

  return absl::OkStatus();
}

static ate_client_ptr ate_client = nullptr;

DLLEXPORT void CreateClient(
    ate_client_ptr *client,    // Out: the created client instance
    client_options_t *options  // In: secure channel attributes
) {
  LOG(INFO) << "debug info: In dll CreateClient";
  AteClient::Options o;

  // convert from ate_client_ptr to AteClient::Options
  o.enable_mtls = options->enable_mtls;
  o.target = options->target;
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
  LOG(INFO) << "debug info: In dll DestroyClient";
  if (ate_client != nullptr) {
    AteClient *ate = reinterpret_cast<AteClient *>(client);
    delete ate;
    ate_client = nullptr;
  }
}

DLLEXPORT int InitSession(ate_client_ptr client, const char *sku,
                          const char *sku_auth) {
  LOG(INFO) << "debug info: In dll InitSession";
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
  LOG(INFO) << "debug info: In dll CloseSession";
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
  LOG(INFO) << "debug info: In dll CreateKeyAndCertificate";
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

// Get the time in milliseconds
uint64_t getMilliseconds() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::high_resolution_clock::now().time_since_epoch())
      .count();
}

DLLEXPORT int RegisterDeviceBMC(
    ate_client_ptr client,          // In:      pointer to the client
    const device_id_t *deviceID,    // In:      Identifies the specific device
    const void *dme_pub_key,        // In:      sec public key
    const size_t dme_pub_key_size,  // In:      sec public key size
    const DeviceLifeCycle life_cycle,  // In:      life_cycle
    const uint8_t year,                // In:      year
    const uint8_t week,                // In:      week
    const uint16_t lot_num,            // In:      lot number
    const uint8_t wafer_id,            // In:      wafer id
    const uint8_t x,                   // In:      x
    const uint8_t y,                   // In:      y
    const void *data,                  // In:      data buffer
    const size_t data_size             // In:      data buffer size
) {
  LOG(INFO) << "debug info: In ate dll RegisterDeviceBMC";

  // Get the time in milliseconds
  auto milliseconds = getMilliseconds();

  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::RegistrationRequest request;
  pa::RegistrationResponse response;

  device_id::DeviceRecord *device_record = request.mutable_device_record();
  // Initialize the device_record message
  device_record->set_sku(ate->Sku);
  //  Initialize the id message
  device_id::DeviceId *id = device_record->mutable_id();
  id->mutable_hardware_origin()->mutable_device_type()->set_silicon_creator(
      (device_id::SiliconCreator)
          deviceID->hardware_origin.device_type.silicon_creator);
  id->mutable_hardware_origin()->mutable_device_type()->set_product_identifier(
      deviceID->hardware_origin.device_type.product_identifier);

  LOG(INFO) << "id->mutable_hardware_origin()->mutable_device_type()->product_"
               "identifier():"
            << id->mutable_hardware_origin()
                   ->mutable_device_type()
                   ->product_identifier();

  id->mutable_hardware_origin()->set_device_identification_number(
      deviceID->hardware_origin.device_identification_number);

  LOG(INFO) << "id->mutable_hardware_origin()->device_identification_number(): "
            << id->mutable_hardware_origin()->device_identification_number();

  id->set_sku_specific(
      std::string((uint8_t *)deviceID->sku_specific,
                  (uint8_t *)deviceID->sku_specific + SKU_SPECIFIC_SIZE));
  id->set_crc32(deviceID->crc32);

  // Initialize the data message
  device_record->mutable_data()->set_device_life_cycle(
      (device_id::DeviceLifeCycle)life_cycle);

  device_id::DeviceIdPub *device_id_pub =
      device_record->mutable_data()->add_device_id_pubs();
  device_id_pub->set_format(
      device_id::DeviceIdPubFormat::DEVICE_ID_PUB_FORMAT_RAW_ECDSA);
  device_id_pub->set_blob(std::string(
      (uint8_t *)dme_pub_key, (uint8_t *)dme_pub_key + dme_pub_key_size));

  device_record->mutable_data()->set_payload(
      (std::string((uint8_t *)data, (uint8_t *)data + data_size)));

  device_record->mutable_data()->mutable_metadata()->set_state(
      device_id::DeviceState::DEVICE_STATE_PROVISIONED);
  device_record->mutable_data()->mutable_metadata()->set_create_time_ms(
      milliseconds);
  device_record->mutable_data()->mutable_metadata()->set_update_time_ms(
      milliseconds);

  device_record->mutable_data()->mutable_metadata()->set_ate_id(ate->ate_id);
  device_record->mutable_data()->mutable_metadata()->set_ate_raw("");
  device_record->mutable_data()->mutable_metadata()->set_year(year);
  device_record->mutable_data()->mutable_metadata()->set_week(week);
  device_record->mutable_data()->mutable_metadata()->set_lot_num(lot_num);
  device_record->mutable_data()->mutable_metadata()->set_wafer_id(wafer_id);
  device_record->mutable_data()->mutable_metadata()->set_y(y);
  device_record->mutable_data()->mutable_metadata()->set_x(x);

  auto status = ate->SendDeviceRegistrationPayload(request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "RegisterDeviceBMC failed with " << status.error_code()
               << ": " << status.error_message();
    return static_cast<int>(status.error_code());
  }
  LOG(INFO) << "return from ATE RegisterDeviceBMC";
  return 0;
}

std::string bytesToStr(uint8_t *byteArray, size_t byteArraySize) {
  std::string str;

  for (size_t i = 0; i < byteArraySize; i++) {
    str += ASCII(((byteArray[i]) >> 4) & 0x0F);
    str += ASCII((byteArray[i]) & 0x0F);
  }
  return str;
}

#define IS_BLOB_CERT_TAG(tag)                                  \
  ((tag == RSA_2048_KEY_CERT) || (tag == RSA_3072_KEY_CERT) || \
   (tag == RSA_4096_KEY_CERT) || (tag == ECC_256_KEY_CERT) ||  \
   (tag == ECC_384_KEY_CERT))

DLLEXPORT int RegisterDeviceTPM(
    ate_client_ptr client,        // In:      pointer to the client
    const device_id_t *deviceID,  // In:      Identifies the specific device
    const void *certs,            // In:      certs
    const size_t certsSize,       // In:      certs size
    const void *pSN,              // In:      serial numbre
    const size_t snSize,          // In:      serial numbre size
    const DeviceLifeCycle life_cycle,  // In:      life_cycle
    const uint8_t year,                // In:      year
    const uint8_t week,                // In:      week
    const uint16_t lot_num,            // In:      lot numbrt
    const uint8_t wafer_id,            // In:      wafer id
    const uint8_t x,                   // In:      x
    const uint8_t y,                   // In:      y
    const char *FT_lot                 // In:      taken from the FT job QR scan
) {
  LOG(INFO) << "debug info: In ate dll RegisterDeviceTPM";

  size_t index = 0;

  // Get the time in milliseconds
  auto milliseconds = getMilliseconds();
  AteClient *ate = reinterpret_cast<AteClient *>(client);

  pa::RegistrationRequest request;
  pa::RegistrationResponse response;

  device_id::DeviceRecord *device_record = request.mutable_device_record();
  // Initialize the device_record message
  device_record->set_sku(ate->Sku);

  //  Initialize the id message
  device_id::DeviceId *id = device_record->mutable_id();
  id->mutable_hardware_origin()->mutable_device_type()->set_silicon_creator(
      (device_id::SiliconCreator)
          deviceID->hardware_origin.device_type.silicon_creator);
  id->mutable_hardware_origin()->mutable_device_type()->set_product_identifier(
      deviceID->hardware_origin.device_type.product_identifier);

  id->mutable_hardware_origin()->set_device_identification_number(
      deviceID->hardware_origin.device_identification_number);
  id->set_sku_specific(
      std::string((uint8_t *)deviceID->sku_specific,
                  (uint8_t *)deviceID->sku_specific + SKU_SPECIFIC_SIZE));
  id->set_crc32(deviceID->crc32);

  LOG(INFO) << "id->mutable_hardware_origin()->mutable_device_type()->product_"
               "identifier(): "
            << id->mutable_hardware_origin()
                   ->mutable_device_type()
                   ->product_identifier();
  LOG(INFO) << "id->mutable_hardware_origin()->device_identification_number(): "
            << id->mutable_hardware_origin()->device_identification_number();
  LOG(INFO) << "id->crc32(): " << id->crc32();

  // Initialize the data message
  device_record->mutable_data()->set_device_life_cycle(
      (device_id::DeviceLifeCycle)life_cycle);

  blob_t *pBlob = (blob_t *)((uint8_t *)certs);
  device_id::DeviceIdPub *device_id_pub = NULL;

  for (index = 0; index < certsSize;) {
    // check that the tag is type is correct
    if (!IS_BLOB_CERT_TAG(pBlob->type)) {
      LOG(ERROR) << "RegisterDeviceTPM failed with wrong/unsupported blob type";
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }
    device_id_pub = device_record->mutable_data()->add_device_id_pubs();
    device_id_pub->set_format(
        device_id::DeviceIdPubFormat::DEVICE_ID_PUB_FORMAT_DER);
    device_id_pub->set_blob(std::string((uint8_t *)pBlob->value,
                                        (uint8_t *)pBlob->value + pBlob->len));

    uint32_t blob_alinment = (4 - (pBlob->len % 4)) % 4;
    index = index + sizeof(pBlob->len) + sizeof(pBlob->type) +
            ((pBlob->len + blob_alinment) & ~blob_alinment);

    if (index > certsSize) {
      LOG(ERROR) << "RegisterDeviceTPM failed with cert blob overflow";
      return static_cast<int>(absl::StatusCode::kInvalidArgument);
    }

    pBlob = (blob_t *)(pBlob->value +
                       ((pBlob->len + blob_alinment) & ~blob_alinment));
  }

  device_record->mutable_data()->mutable_metadata()->set_state(
      device_id::DeviceState::DEVICE_STATE_PROVISIONED);
  device_record->mutable_data()->mutable_metadata()->set_create_time_ms(
      milliseconds);
  device_record->mutable_data()->mutable_metadata()->set_update_time_ms(
      milliseconds);
  device_record->mutable_data()->mutable_metadata()->set_ate_raw(
      bytesToStr((uint8_t *)pSN, snSize));
  device_record->mutable_data()->mutable_metadata()->set_ate_id(ate->ate_id);
  device_record->mutable_data()->mutable_metadata()->set_year(year);
  device_record->mutable_data()->mutable_metadata()->set_week(week);
  device_record->mutable_data()->mutable_metadata()->set_lot_num(lot_num);
  device_record->mutable_data()->mutable_metadata()->set_wafer_id(wafer_id);
  device_record->mutable_data()->mutable_metadata()->set_y(y);
  device_record->mutable_data()->mutable_metadata()->set_x(x);

  auto status = ate->SendDeviceRegistrationPayload(request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "RegisterDeviceTPM failed with " << status.error_code()
               << ": " << status.error_message();
    return static_cast<int>(status.error_code());
  }
  LOG(INFO) << "return from ATE RegisterDeviceTPM";
  return 0;
}
