# Deployment Guide

## System Requirements

Currently, Ubuntu 22.04LTS is the only supported deployment environment. The
following steps need to be executed manually to prepare the system for
deployment. In the future, these steps will be migrated to Ansible scripts.

See [Ansible documentation](https://docs.ansible.com/ansible/latest/index.html)
for more details.

1. The following packages need to be installed before configuring the provisioning
services.

    ```console
    # Install system dependencies.
    sudo apt update && sudo apt install \
        openssl \
        ca-certificates \
        libssl-dev \
        podman \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-wheel
    ```

## Service Deployment

The current deployment uses `podman play kube` to start the `spm` and `pa`
containers using `podman` as the container engine. The service configuration
is maintained in the Kubernetes
[config/containers/provapp.yml](../config/containers/provapp.yml)
configuration file.


1. Download release artifacts into a staging directory. The following
instructions use `${STAGING_DIR}` to point to it.

    ```console
    # Get scripts and configuration files.
    $ cd ${STAGING_DIR}
    $ tar -xvf deploy_dev.tar.xz

    # Run deploy script
    $ ./deploy.sh $PWD
    Storing signatures
    Loaded image(s): localhost/pa_server:latest,localhost/spm_server:latest
    Launching containers
    Pod:
    cd208245e1d1195a7adfb073857cf2a4def9ecd9c7543a7af9906428ad536454
    Containers:
    48c834ed73f4153e9652a32dade2edc16f07dbc38ce1f55920e871907f155b98
    a198c59630f13987fbd2fbfe37593920adb5b26f7c0b6c987e6a9a441af1109b
    ```

1. Configure a `systemctl` service to restart the service on system reboot:

    ```console
    $ cp ${STAGING_DIR}/containers/provapp.service ~/.config/systemd/user/.
    $ systemctl --user enable provapp.service
    $ systemctl --user start provapp.service
    ```

1. (Optional) Use the following command to execute the PA server load test:

    ```console
    $ ${OPENTITAN_VAR_DIR}/release/loadtest \
        --enable_tls=false \
        --pa_address="localhost:5001" \
        --parallel_clients=20 \
        --total_calls_per_method=10
    ```

1. (Optional) Run the previous step after system reboot.

### Infra (pause) Container

In Kubernetes compatible deployments, the provisioning services run inside a
`pause` container whose main task is to maintain resource reservations for the
lifetime of the pod. The provisioning infrastructure packages a `podman_pause`
container to enable offline deployments. In order to enable the use of the
prepackaged `podman_pause` container, the following setting must be added to
the appropiate container configuration file:

```
[engine]
infra_image = "podman_pause:latest"
```

This is currently done by the deployment script, which configures the services
in rootless mode.

## Local Testing

The following steps can be used to test the install from a development environment:

```console
# Build the release packages
$ bazelisk build //release

# Deploy the containers.
$ config/deploy.sh bazel-bin/release

# Run load test.
$ ${OPENTITAN_VAR_DIR}/release/loadtest \
    --enable_tls=false \
    --pa_address="localhost:5001" \
    --parallel_clients=20 \
    --total_calls_per_method=10
```