# Secure Provisioning Module (SPM)

The Secure Provisioning Module (SPM) is part of the
[Provisioning Appliance](pa.md) (PA), and is responsible for implementing
secure operations (e.g. signing with a private manufacturer key). The SPM may
interface to an HSM or a Secure Element (SE), used to implement physical
protection.

The SPM exposes a service interface to the PA defined in protobuf format.
See [`src/pa/services/pa.go`](../src/pa/proto/pa.proto) for more details.

## Configuration Files

The SPM server is configured to point to a configuration directory using the
`--spm_config_dir` flag. In this directory each SKU must contain a
configuration file in YAML format using the following naming convention:

```
sku_<SKU_NAME>.yml
```

`SKU_NAME` is the SKU identifier used in service calls.

All files referenced by any configuration file must be relative to the
`--spm_config_dir` directory.

## Handling Secrets

The SPM source code does not contain any secrets, and HSM credentials are
configured using environment variables. See
[spm.env](../config/dev/env/spm.env) for details. The following secrets are
required by the SPM binary:

* `SPM_HSM_PIN_ADMIN`: The HSM Security Officer (SO) pin.
* `SPM_HSM_PIN_USER`: The HSM User (SU) pin.

## Developer Notes

The following section describes how to run the SPM server in development mode.
For SoftHSM2 initialization use `--local` option if more than one developer is
using the system to avoid conflicts (no sudo is required).

See `run_integration_tests.sh` for an example of how to configure and run
the SPM and PA servers.

### Configure SoftHSM2

The following instructions build softHSM and initializes an HSM slot with
expected security officer and operator pin values, as well as the keys required
to configure the current SKU supported by the SPM service.

Execute the following commands from the root of the repo:

```console
$ bazelisk build @softhsm2//:softhsm2
$ . config/dev/env/spm.env
$ config/dev/softhsm/init.sh \
    config/dev \
    bazel-bin/external/softhsm2/softhsm2 \
    /var/lib/opentitan
refresh: The object generation has not been updated
        Manufacturer ID:  SoftHSM project
        Model:            SoftHSM v2
        Hardware version: 2.6
        Firmware version: 2.6
        Serial number:    7381e8d7a197e098
        Initialized:      yes
        User PIN init.:   yes
        Label:            SoftToken
...
Execute the following command before launching the spm service:
export SOFTHSM2_CONF=/var/lib/opentitan/spm/softhsm2/softhsm2.conf
SoftHSM configuration available at: PASS!
```

NOTE: The last parameter can be updated to point to a local path if planning
to run outside of a container. For example:

```console
$ config/dev/softhsm/init.sh \
    config/dev \
    bazel-bin/external/softhsm2/softhsm2 \
    "$(pwd)/.opentitan
Execute the following command before launching the spm service:
export SOFTHSM2_CONF=/home/user/ot-provisioning/.opentitan/spm/softhsm2/softhsm2.conf
SoftHSM configuration result: PASS!
```

### Initialize Keys

The following command initializes the keys in the HSM for test purposes.

Note: The `--force_keygen` flag deletes previous SKU keys in the HSM.

**SoftHSM**

```console
$ . config/dev/env/spm.env
$ bazelisk run //src/spm:spmutil -- \
    --hsm_pw=${SPM_HSM_PIN_USER} \
    --hsm_so=${OPENTITAN_VAR_DIR}/softhsm2/libsofthsm2.so \
    --hsm_type=0 \
    --hsm_slot=0 \
    --force_keygen \
    --gen_kg \
    --gen_kca \
    --load_low_sec_ks \
    --low_sec_ks="0x23df79a8052010ef6e3d49255b606f871cff06170247c1145ebb71ad23834061" \
    --load_high_sec_ks \
    --high_sec_ks="0xaba9d5616e5a7c18b9a41d8a22f42d4dc3bafa9ca1fad01e404e708b1eab21fd" \
    --ca_outfile=${OPENTITAN_VAR_DIR}/spm/config/certs/NuvotonTPMRootCA0200.cer
```

**LunaHSM**

```console
# Load relevant environment variables beforehand.
$ bazelisk run //src/spm:spmutil -- \
    --hsm_pw=${SPM_HSM_PIN_USER} \
    --hsm_so=/usr/safenet/lunaclient/lib/libCryptoki2_64.so \
    --hsm_type=1 \
    --hsm_slot=0 \
    --force_keygen \
    --gen_kg \
    --gen_kca \
    --load_low_sec_ks \
    --low_sec_ks="0x23df79a8052010ef6e3d49255b606f871cff06170247c1145ebb71ad23834061" \
    --load_high_sec_ks \
    --high_sec_ks="0xaba9d5616e5a7c18b9a41d8a22f42d4dc3bafa9ca1fad01e404e708b1eab21fd" \
    --ca_outfile=${OPENTITAN_VAR_DIR}/spm/config/certs/NuvotonTPMRootCA0200.cer
```

### Start SPM Server

Run the following steps before proceeding.

* Generate [enpoint certificates](auth.md#endpoint-certificates).
* Initialize the [softHSM2 token](#configure-softhsm2).

Start the SPM server after setting the SoftHSM2 envars with mTLS enabled.

```console
$ source config/dev/env/spm.env
$ bazelisk build //src/spm:spm_server
$ bazel-bin/src/spm/spm_server_/spm_server --port=5000 \
    --enable_tls=true \
    --service_key=$(pwd)/config/dev/certs/out/spm-service-key.pem \
    --service_cert=$(pwd)/config/dev/certs/out/spm-service-cert.pem \
    --ca_root_certs=$(pwd)/config/dev/certs/out/ca-cert.pem \
    --hsm_so=$(pwd)/bazel-bin/external/softhsm2/softhsm2/lib/softhsm/libsofthsm2.so \
    --spm_config_dir=$(pwd)/config/dev/spm
YYYY/mm/DD HH:MM:DD Server is now listening on port: 5000
```

## Read More

* [Provisioning Appliance](pa.md)
* [Documentation index](README.md)
