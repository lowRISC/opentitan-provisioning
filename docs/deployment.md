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

A release consists of a `release_bundle.tar.xz` file and several container
image archives (`.tar` files). The following steps describe how to deploy the
services. It is assumed that `${OPENTITAN_VAR_DIR}` is set to the desired
installation directory (e.g., `/opt/opentitan-prov`).

1. Download release artifacts into a staging directory. The following
   instructions use `${STAGING_DIR}` to point to it. A typical release will
   contain the following files:

    ```
    fakeregistry_containers.tar
    provisioning_appliance_containers.tar
    proxybuffer_containers.tar
    release_bundle.tar.xz
    softhsm_dev.tar.xz
    ```

2. Prepare the deployment directories and copy the release artifacts. All
   services will be installed under the `${OPENTITAN_VAR_DIR}` directory.

    ```console
    # Create installation directories.
    $ sudo mkdir -p ${OPENTITAN_VAR_DIR}/release

    # Copy release bundle.
    $ sudo cp ${STAGING_DIR}/release_bundle.tar.xz ${OPENTITAN_VAR_DIR}/

    # Copy container images and other artifacts.
    $ sudo cp ${STAGING_DIR}/*_containers.tar ${OPENTITAN_VAR_DIR}/release/
    $ sudo cp ${STAGING_DIR}/softhsm_dev.tar.xz ${OPENTITAN_VAR_DIR}/release/
    ```

3. Extract the release bundle and configuration.

    ```console
    $ sudo tar xvf ${OPENTITAN_VAR_DIR}/release_bundle.tar.xz -C ${OPENTITAN_VAR_DIR}
    $ sudo tar xvf ${OPENTITAN_VAR_DIR}/config/config.tar.gz -C ${OPENTITAN_VAR_DIR}
    ```

4. Run the deployment script. The script takes the deployment environment as an
   argument. This can be `prod` or `dev`.

    ```console
    $ export DEPLOY_ENV="prod"
    $ sudo ${OPENTITAN_VAR_DIR}/config/deploy.sh ${DEPLOY_ENV}
    Storing signatures
    Loaded image(s): localhost/pa_server:latest,localhost/spm_server:latest
    Launching containers
    Pod:
    cd208245e1d1195a7adfb073857cf2a4def9ecd9c7543a7af9906428ad536454
    Containers:
    48c834ed73f4153e9652a32dade2edc16f07dbc38ce1f55920e871907f155b98
    a198c59630f13987fbd2fbfe37593920adb5b26f7c0b6c987e6a9a441af1109b
    ```

5. Configure a `systemctl` service to restart the service on system reboot:

    ```console
    $ cp ${OPENTITAN_VAR_DIR}/config/provapp.service ~/.config/systemd/user/.
    $ systemctl --user enable provapp.service
    $ systemctl --user start provapp.service
    ```

6. (Optional) Initialize tokens. If the deployment uses an HSM, it may be
   necessary to initialize the tokens. This script currently used in `dev`
   mode. The `prod` configuration requires interacting with an offline 
   HSM, so it is recommended to call the HSM initialization scripts
   directly.

    ```console
    $ if [ -f "${OPENTITAN_VAR_DIR}/config/token_init.sh" ]; then
        echo "Initializing tokens ..."
        sudo DEPLOY_ENV="${DEPLOY_ENV}" ${OPENTITAN_VAR_DIR}/config/token_init.sh
    fi
    ```

7. (Optional) Use the following command to execute the PA server load test:

    ```console
    $ ${OPENTITAN_VAR_DIR}/release/loadtest \
        --enable_tls=false \
        --pa_address="localhost:5001" \
        --parallel_clients=20 \
        --total_calls_per_method=10
    ```

8. (Optional) Run the previous step after system reboot.

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
# The integation test invokes the deploy script to initialize the test environment.
# The following flags can be used:
# * --debug: Skips tearing down of containers. Useful if access to container logs
#   is required.
# * --prod: Builds and deploys the test environment using the test configuration. 
#   This involves connecting to a physical HSM.
FPGA=skip ./run_integration_tests.sh
```