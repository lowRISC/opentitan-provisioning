// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Protobuf's port_def.inc defines PROTOBUF_DESCRIPTOR_WEAK_MESSAGES_ALLOWED
// whenever __clang__ is defined and _MSC_VER is not, assuming ELF targets where
// the linker synthesizes __start_pb_defaults and __stop_pb_defaults around the
// non-empty `pb_defaults` section. Clang's optimizer also folds `start != end`
// to true on entry because they are distinct extern declarations.
//
// On MinGW (PE-COFF), lld does not synthesize those section boundary symbols.
// We provide a single writable 12-byte DummyWeakDefault entry in .data
// bracketed by ___start_pb_defaults and ___stop_pb_defaults so
// InitWeakDefaults() performs one harmless self-store and exits cleanly.
__asm__(
    ".data\n"
    ".balign 4\n"
    ".globl ___start_pb_defaults\n"
    "___start_pb_defaults:\n"
    ".long 0\n"
    ".long ___start_pb_defaults\n"
    ".long 12\n"
    ".globl ___stop_pb_defaults\n"
    "___stop_pb_defaults:\n");
