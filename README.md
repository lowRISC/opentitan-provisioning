[//]: # (Copyright lowRISC contributors \(OpenTitan project\).)
[//]: # (Licensed under the Apache License, Version 2.0, see LICENSE for details.)
[//]: # (SPDX-License-Identifier: Apache-2.0)

# OpenTitan Provisioning Infrastructure

## Getting Started

### System Requirements

Currently, Ubuntu 22.04LTS is the only supported development environment. There
are [build container](docs/containers.md#building-inside-the-build-container)
instructions available for other OS distributions.

### Install Dependencies

Install dependencies via `setup.sh`. This will run `apt` to install system-level
dependencies, and install `bazelisk`, a Bazel wrapper that simplifies version
selection.

### Add bazelisk to PATH

Make sure to add `${GOPATH}/bin` to your path, e.g.:

```console
$ export PATH="$PATH:$(go env GOPATH)/bin"
```

### Runing Build Commands

To build and run unit tests:

```console
$ bazelisk test //...
```

To run integration test cases:

```console
$ ./run_integration_tests.sh
```

To format the code before submitting changes:

```console
$ bazelisk run //quality:buildifier_fix
$ bazelisk run //quality:gofmt
$ bazelisk run //quality:clang_format
```

## GitHub Releases

The release process assumes you have your git and
[GitHub CLI](https://cli.github.com/) credentials in `$HOME/.git` and
`$HOME/.config/gh` repsectively.

1. Commit your changes.
2. Create a tag locally before running the build command.

   ```console
   OT_GIT_TAG=v0.0.1pre1
   git tag ${OT_GIT_TAG}
   ```

3. Run the release command.  `util/get_workspace_status.sh` captures the git
   tag in the binaries when using the `--stamp` build flag.

   ```console
   $ bazelisk run --stamp //release -- ${OT_GIT_TAG} -p
   ```

## Read More

* [Contribution Guide](docs/contributing.md)
* [Deployment Guide](docs/deployment.md)
* [Documentation index](docs/README.md)
