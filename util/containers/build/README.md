# Build Docker Container

This Docker container may be used to build and develop code in this repository
if your development environment is not a Ubuntu22.04 environment.

## Local Build Instructions

Skip this step if planning to use the pre-built container. To build in local
mode:

```shell
cd $REPO_TOP
util/containers/build/build_container.sh
```

## Using the Container

Run the container using the `run.sh` script as shown below. The `root` user
inside the container is mapped to the `${USER}` on the host side.

```shell
cd ${REPO_TOP}
util/containers/build/run.sh
```
