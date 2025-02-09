# Provisioning Appliance

The Provisioning Service is used for securely (wrapped) storing SKU material
(e.g. SKU keys, leaf CA keys and certificate template) generated and packed
in an offline HSM and provisioning the SKU material into the [SPM](spm.md).

The Provisioning Appliance Service definition is defined in a protobuf file
under [`src/pa/proto/pa.proto`](../src/pa/proto/pa.proto).

## Developer Notes

### Start PA Server

Run the following steps before proceeding.

* Generate [enpoint certificates](auth.md#endpoint-certificates).
* Start [SPM server](spm.md#start-spm-server).

Start the server with mTLS enabled. The Provisioning Appliance (PA) connects to the
SPM at startup time.

```console
$ bazelisk build //src/pa:pa_server
$ bazel-bin/src/pa/pa_server_/pa_server --port=5001 \
    --spm_address="localhost:5000" \
    --enable_tls=true \
    --service_key=$(pwd)/config/dev/certs/out/pa-service-key.pem \
    --service_cert=$(pwd)/config/dev/certs/out/pa-service-cert.pem \
    --ca_root_certs=$(pwd)/config/dev/certs/out/ca-cert.pem
YYYY/mm/DD 22:28:09 starting SPM client at address: "localhost:5000"
YYYY/mm/DD 22:28:09 server is now listening on port: 5001
```

### Load Test

The following command can be used to execute a PA server load test:

```console
$ bazelisk run //src/pa:loadtest -- \
    --enable_tls=true \
    --client_cert=$(pwd)/config/dev/certs/out/ate-client-cert.pem \
    --client_key=$(pwd)/config/dev/certs/out/ate-client-key.pem \
    --ca_root_certs=$(pwd)/config/dev/certs/out/ca-cert.pem \
    --pa_address="localhost:5001" \
    --parallel_clients=20 \
    --total_calls_per_method=100
```

## Read More

* [Secure Provisioning Module](spm.md)
* [Documentation index](README.md)
