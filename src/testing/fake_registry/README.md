[//]: # (Copyright lowRISC contributors \(OpenTitan project\).)
[//]: # (Licensed under the Apache License, Version 2.0, see LICENSE for details.)
[//]: # (SPDX-License-Identifier: Apache-2.0)

# Fake registry

This package contains a fake HTTP registry to be used for testing.

## Usage

```
bazelisk run //src/testing/fake_registry:fake_registry_server
```

## Flags

- `port`: specifies the port in which the server listens. Defaults to 9999.
- `register_device_url`: URL to listen to RegisterDevice requests. Defaults to
  `/registerDevice`.
- `batch_register_device_url`: URL to listen to BatchRegisterDevice requests.
  Defaults to `/batchRegisterDevice`.
