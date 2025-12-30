# MinGW-w64 Toolchain Adapter

This directory contains the local configuration and wrapper scripts for the MinGW-w64 cross-compiler toolchain used to build Windows artifacts on Linux.

## Origin

These files are adapted from the [lowRISC/crt](https://github.com/lowRISC/crt) repository. They serve as an adapter layer to bridge the generic toolchain definitions in `crt` with this project's specific Bzlmod build environment.

## Why are these files local?

Directly depending on the upstream `crt` toolchain definitions is not feasible due to **Bzlmod compatibility**:

1.  **Repository Names:** Bzlmod generates complex, canonical repository names (e.g., `external/_main~_repo_rules~gcc_mxe_mingw32_files`) that differ from the simple names used in legacy `WORKSPACE` setups.
2.  **Dynamic Path Resolution:** The upstream `driver.sh` expects a fixed path structure. Our local `wrappers/driver.sh` includes custom logic to dynamically find the correct directory in `external/`, ensuring the toolchain works regardless of how Bzlmod mangles the repository name.
3.  **Include Paths:** `BUILD.bazel` hardcodes `SYSTEM_INCLUDE_PATHS` that point to specific Bzlmod directories. These paths are unique to this project's module graph and cannot be genericized in the upstream repository.

## Structure

*   **`BUILD.bazel`**: Defines the toolchain using the `setup` macro from `@crt`. It injects the project-specific system include paths.
*   **`wrappers/`**: Contains symlinks (e.g., `gcc`, `ld`) that all point to `driver.sh`.
*   **`wrappers/driver.sh`**: The entry point for all toolchain commands. It:
    1.  Locates the actual compiler binaries in `external/`.
    2.  Sets up environment variables (`COMPILER_PATH`, `LIBRARY_PATH`).
    3.  Invokes the real binary with the correct arguments.
