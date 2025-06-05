# Provisioning Appliance

The Provisioning Service is used for securely (wrapped) storing SKU material
(e.g. SKU keys, leaf CA keys and certificate template) generated and packed
in an offline HSM and provisioning the SKU material into the [SPM](https://github.com/lowRISC/opentitan-provisioning/wiki/spm).

The Provisioning Appliance Service definition is defined in a protobuf file
under [`src/pa/proto/pa.proto`](https://github.com/lowRISC/opentitan-provisioning/blob/main/src/pa/proto/pa.proto).

## Developer Notes

### Start Proxy buffer

The proxy buffer service is required by the `loadtest`.

```console
$ source config/env/certs.env
$ bazel build //src/proxy_buffer:pb_server
$ bazel-bin/src/proxy_buffer/pb_server_/pb_server \
    --enable_tls=true \
    --service_key=${OPENTITAN_VAR_DIR}/config/certs/out/pb-service-key.pem \
    --service_cert=${OPENTITAN_VAR_DIR}/config/certs/out/pb-service-cert.pem \
    --ca_root_certs=${OPENTITAN_VAR_DIR}/config/certs/out/ca-cert.pem \
    --port=${OTPROV_PORT_PB} \
    --db_path=file::memory:?cache=shared
```

### Start PA Server

Run the following steps before proceeding.

* Generate [enpoint certificates](https://github.com/lowRISC/opentitan-provisioning/wiki/auth#endpoint-certificates).
* Start [SPM server](https://github.com/lowRISC/opentitan-provisioning/wiki/spm#start-spm-server).

Start the server with mTLS enabled. The Provisioning Appliance (PA) connects to the
SPM at startup time.

```console
$ source config/env/certs.env
$ bazel build //src/pa:pa_server
$ bazel-bin/src/pa/pa_server_/pa_server \
    --port=${OTPROV_PORT_PA} \
    --spm_address="${OTPROV_DNS_SPM}:${OTPROV_PORT_SPM}" \
    --enable_registry \
    --registry_address="${OTPROV_DNS_PB}:${OTPROV_PORT_PB}" \
    --enable_tls=true \
    --service_key=${OPENTITAN_VAR_DIR}/config/certs/out/pa-service-key.pem \
    --service_cert=${OPENTITAN_VAR_DIR}/config/certs/out/pa-service-cert.pem \
    --ca_root_certs=${OPENTITAN_VAR_DIR}/config/certs/out/ca-cert.pem
YYYY/mm/DD 22:28:09 starting SPM client at address: "localhost:5000"
YYYY/mm/DD 22:28:09 server is now listening on port: 5001
```

### Load Test

The following command can be used to execute a PA server load test:

```console
$ bazel run //src/pa:loadtest -- \
    --enable_tls=true \
    --client_cert=${OPENTITAN_VAR_DIR}/config/certs/out/ate-client-cert.pem \
    --client_key=${OPENTITAN_VAR_DIR}/config/certs/out/ate-client-key.pem \
    --ca_root_certs=${OPENTITAN_VAR_DIR}/config/certs/out/ca-cert.pem \
    --pa_address="${OTPROV_DNS_PA}:${OTPROV_PORT_PA}" \
    --parallel_clients=20 \
    --total_calls_per_method=100
```

## Read More

* [Secure Provisioning Module](https://github.com/lowRISC/opentitan-provisioning/wiki/spm)
* [Documentation index](https://github.com/lowRISC/opentitan-provisioning/wiki/Home)
