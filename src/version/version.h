// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef OPENTITAN_PROVISIONING_SRC_VERSION_VERSION_H_
#define OPENTITAN_PROVISIONING_SRC_VERSION_VERSION_H_

#include <string>

namespace provisioning {

/**
 * Returns the build hostname injected by Bazel.
 */
const char* BuildHost();

/**
 * Returns the build user injected by Bazel.
 */
const char* BuildUser();

/**
 * Returns the the build timestamp injected by Bazel.
 */
const char* BuildTimestamp();

/**
 * Returns the repository release tag or commit hash injected by Bazel.
 */
const char* BuildRevision();

/**
 * Returns the status of the repository injected by Bazel.
 */
const char* BuildStatus();

/**
 * Returns a formatted string version which can be used to reference the target
 * release.
 */
std::string VersionFormatted();

}  // namespace provisioning

#endif  // OPENTITAN_PROVISIONING_SRC_VERSION_VERSION_H_
