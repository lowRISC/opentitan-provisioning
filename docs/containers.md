# Containers

All the provisioning system components are deployed using containers to
simplify binary configuration, and make it easier to run across different
environments. For example, we want to be able to deploy a staging version of
the system in a cloud environment for the purpose of running integration tests.

## Container Configuration

This project uses [`rules_docker`](https://github.com/bazelbuild/rules_docker)
to build container images without requiring the use of `docker` or `podman`.

Most containers are built using distroless targets, to minimize the memory
footprint and dependencies attack surface.

### SPM Caveats

Once exception to the distroless container rule is the `SPM` build target,
which requires the ability to load pkcs#11 shared libraries compiled outside
the Bazel sandbox. The SPM is built on top of an `Ubuntu 22.04LTS` base image
which reproduces the runtime dependencies of the shared libraries.

## Building Inside the Build Container

Some shared library targets break the Bazel sandbox isolation, making it
difficult to build outside a container. For example, the
`@softhsm2//:softhsm2` target uses `cmake` to build the shared library,
which requires calling into `packageconfig` to locate the `libssl-dev`
system install. Using a build container with the same runtime configuration
as the target helps us avoid runtime dependency issues.

The following commands illustrate how to build the containers:

```console
# Build the build container. Only needs to be done once, or whenever there
# are updates required to the build container.
$ util/containers/build/build_container.sh

# Start the build container. This will take care of mapping the Bazel .cache
# to a location accessible to both the container and the host ${USER}.
$ util/containers/build/run.sh

# Build the containers.
$ bazelisk build :provisioning_appliance_containers

# Exit the container once done building.
$ exit

# Load the containers into your local container repository.

$ bazel-bin/provisioning_appliance_containers
Loaded image(s): sha256:c2b42c3a32d9ee0ff650fbc24af5b87da0f41b934a74b2c0d929a5298812a76b
Tagging de73c2c15f3cfdd7e75b6656938d3d19cffff98581dbbc0eff01e0477987e343 as pa_server
Tagging c2b42c3a32d9ee0ff650fbc24af5b87da0f41b934a74b2c0d929a5298812a76b as spm_server
```

After this, the containers will be available with the following tags:

* `spm_server:latest`
* `pa_server:latest`

The result `bazel-bin/provisioning_appliance_containers` binary and associated
runtime folder can be used to deploy the containers on premises (e.g. factory
environment), or uploaded into a container cloud registry. See the
[`provisioning_appliance_containers`](../BUILD.bazel) build target for
more details on how the images are packaged.

## Next Steps

The following topics will be covered in the future:

* Build versioning.
* Container orchestration.
  * Deployment environment
  * Network settings
  * Security
  * Host device mapping

## Read More

* [Documentation index](https://github.com/lowRISC/opentitan-provisioning/wiki/README.md)
