# CRT Toolchain Vendor Directory

This directory contains the vendored configuration, rules, and platform definitions for the `crt` (Compiler Runtime) toolchain, specifically configured for OpenTitan provisioning tasks (e.g., Windows cross-compilation).

## Origin

The contents of this directory were consolidated from various parts of the repository to create a self-contained toolchain definition.

- **Upstream Project:** [lowRISC/crt](https://github.com/lowRISC/crt)
- **Binaries:** The actual toolchain binaries (GCC MinGW) are fetched as an `http_archive` defined in `MODULE.bazel`.

## Structure

- `config/`: Compiler and device configuration Starlark files (formerly in `//config`).
- `features/`: Feature definitions for the toolchain (formerly in `//features`).
- `platforms/`: Platform definitions, specifically for `x86_32` Windows (formerly in `//platforms`).
- `rules/`: Custom Bazel rules for the toolchain, such as `pkg_win` (formerly in `//rules`).
- `toolchains/`: Toolchain definitions and wrappers (formerly in `//toolchains`).
- `util/`: Helper scripts and utilities (formerly in `//util`).

## Usage

These files are used to configure the C++ toolchain for cross-compiling to Windows. The entry points are primarily in `MODULE.bazel` (registering the toolchain) and the `BUILD.bazel` files within this directory structure.
