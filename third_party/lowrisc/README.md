# Updating the Bitstreams

CW310 and CW340 bitstreams are checked into this repo (using Git LFS) to enable emulating provisioning flow on an OpenTitan FPGA DUT.
The bitstreams checked into this repo represent the state of a chip as it would be if it were entering CP, meaning the chip has a completely empty OTP and flash, except the lifecycle state is TEST\_UNLOCKED0.
To update these bitstreams with the latest pinned version of the lowrisc\_opentitan repo, do the following:
1. Make sure the `_OPENTITAN_VERSION` tag in `third_party/lowrisc/repos.bzl` matches the `_OT_REPO_BRANCH` tag in `third_party/lowrisc/ot_bitstreams/build-ot-bitstreams.sh`.
1. `./third_party/lowrisc/ot_bitstreams/build-ot-bitstreams.sh <path to opentitan repo>`
1. `git add third_party/lowrisc/ot_bitstreams/cp_cw340.bit`
1. `git add third_party/lowrisc/ot_bitstreams/cp_hyper310.bit`
1. Commit the updated bitstreams.

# Updating the Provisioning Firmware (orchestrator.zip)

OpenTitan provisioning firmware is built and packaged into a ZIP file in the upstream lowrisc\_opentitan Bazel repo.
This firmware is used to run E2E test provisioning flows with the provisioning infrastructure in this repo, and therefore is checked into this repo (using Git LFS).
To update the checked-in firmware ZIP file, do the following:
1. Make sure the `_OPENTITAN_VERSION` tag in `third_party/lowrisc/repos.bzl` matches the `_OT_REPO_BRANCH` tag in `third_party/lowrisc/ot_fw/build-orch-zip.sh`.
1. `./third_party/lowrisc/ot_fw/build-orch-zip.sh <path to opentitan repo>`
1. `git add third_party/lowrisc/ot_fw/orchestrator.zip`
1. Commit the updated firmware ZIP file.
