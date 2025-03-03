# Integrating with Vendor-Specific Registry Services

The ProvisioningAppliance (PA) provides an RPC function (`RegisterDevice`) to register a provisioned device with a registry service (and backend database storage layer).
The PA's upstream implementation of the `RegisterDevice` RPC takes as input a `RegistryRecord` proto message and forwards it along to the ProxyBuffer service.
The `RegistryRecord` message is designed to be simple, yet flexible, and contains the following fields:
1. `device_id` - encoded as a hex string
1. `sku` - encoded as a string
1. `version` - encoded as a uint32
1. `data` - encoded as a generic array of bytes
By default, the PA marshalls the [`ot.DeviceData`](src/proto/device_id.proto) message into the `data` field using the default [`registry_shim`](src/pa/services/registry_shim/registry_shim.go) library.
However, the upstream implementation of the PA provides a mechanism to override the `registry_shim` library with a vendor-specific implementation of the `registry_shim` library to enable vendors to pack any data they require into the generic `data` bytes field of the `RegistryRecord` proto.
This override mechanism is described in detail below.

# Implementing a Custom `registry_shim` Library

To implement a custom `registry_shim` library to enable packing any vendor-specific data into the `RegistryRecord.data field`, follow the steps below:
1. Copy/Paste the `$(REPO_TOP)/src/vendor` directory to another location on your system.
1. Modify the `RegisterDevice` function in the new `registry_shim.go` file you copy/pasted to a new location on your system, e.g., `/path/to/location_of/vendor/registry_shim/registry_shim.go`. You should modify the function to unpack/repack the `ot.DeviceData` message into the desired format your Registry Service requires.
1. Set the `VENDOR_REPO_DIR` envar to point to the location of the `$(REPO_TOP)/src/vendor` directory you copy/pasted on your system: `export VENDOR_REPO_DIR="/path/to/vendor"`.
1. Build your modified PA binary with `bazelisk build --//src/pa/services:use_vendor_shim //src/pa/services:pa`.
