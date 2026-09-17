// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Win32 smoke-test host for the shipped ATE DLL.
//
// This mirrors how an ATE vendor consumes the release artifact: it loads
// `ate.dll` with LoadLibrary() and calls the exported `CreateClient()` entry
// point. No provisioning appliance is required: `CreateClient()` only builds
// the gRPC channel (connection establishment is lazy), which is enough to
// catch crashes in gRPC's static initialization / channel construction code
// on the 32-bit MinGW toolchain.
//
// Exit codes:
//   0  - CreateClient() succeeded.
//   1  - CreateClient() returned an error status.
//   2  - harness setup error (DLL missing, symbol missing, ...).
//   42 - the process took an unhandled exception (e.g. access violation).

#include <windows.h>

#include <cstdio>
#include <cstring>

#include "ate_api.h"

namespace {

typedef int (*CreateClientFn)(ate_client_ptr *, client_options_t *);
typedef void (*DestroyClientFn)(ate_client_ptr);
typedef int (*InitSessionFn)(ate_client_ptr, const char *, const char *);
typedef int (*CloseSessionFn)(ate_client_ptr);

constexpr int kSetupError = 2;
constexpr int kCrashExitCode = 42;

// Reports unhandled exceptions (such as the 0xC0000005 access violation seen
// with miscompiled gRPC code) with a deterministic exit code instead of
// popping up a debugger.
LONG WINAPI CrashFilter(EXCEPTION_POINTERS *info) {
  std::printf("[ate_dll_smoke] CRASH code=0x%08lx addr=%p\n",
              static_cast<unsigned long>(info->ExceptionRecord->ExceptionCode),
              info->ExceptionRecord->ExceptionAddress);
  if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
      info->ExceptionRecord->NumberParameters >= 2) {
    std::printf(
        "[ate_dll_smoke] access violation %s address 0x%08lx\n",
        info->ExceptionRecord->ExceptionInformation[0] ? "writing" : "reading",
        static_cast<unsigned long>(
            info->ExceptionRecord->ExceptionInformation[1]));
  }
  std::fflush(stdout);
  TerminateProcess(GetCurrentProcess(), kCrashExitCode);
  return EXCEPTION_EXECUTE_HANDLER;
}

void PrintUsage(const char *argv0) {
  std::printf(
      "usage: %s [--dll=ate.dll] [--mtls] [--mlkem] [--mldsa]\n"
      "          [--cert=PATH] [--key=PATH] [--ca=PATH] [--target=ADDR]\n"
      "          [--sku=NAME --sku_auth=PASSWORD]\n"
      "\n"
      "When --sku and --sku_auth are given, the harness additionally runs\n"
      "InitSession()/CloseSession() against the target, which requires a live\n"
      "Provisioning Appliance.\n",
      argv0);
}

const char *FlagValue(const char *arg, const char *name) {
  size_t len = std::strlen(name);
  if (std::strncmp(arg, name, len) == 0 && arg[len] == '=') {
    return arg + len + 1;
  }
  return nullptr;
}

}  // namespace

int main(int argc, char **argv) {
  const char *dll_path = "ate.dll";
  const char *cert = "certs/ate-client-cert.pem";
  const char *key = "certs/ate-client-key.pem";
  const char *ca = "certs/ca-cert.pem";
  const char *target = "localhost:5000";
  const char *sku = "";
  const char *sku_auth = "";
  bool mtls = false;
  bool mlkem = false;
  bool mldsa = false;

  for (int i = 1; i < argc; ++i) {
    const char *value = nullptr;
    if (std::strcmp(argv[i], "--mtls") == 0) {
      mtls = true;
    } else if (std::strcmp(argv[i], "--mlkem") == 0) {
      mlkem = true;
    } else if (std::strcmp(argv[i], "--mldsa") == 0) {
      mldsa = true;
    } else if ((value = FlagValue(argv[i], "--dll")) != nullptr) {
      dll_path = value;
    } else if ((value = FlagValue(argv[i], "--cert")) != nullptr) {
      cert = value;
    } else if ((value = FlagValue(argv[i], "--key")) != nullptr) {
      key = value;
    } else if ((value = FlagValue(argv[i], "--ca")) != nullptr) {
      ca = value;
    } else if ((value = FlagValue(argv[i], "--target")) != nullptr) {
      target = value;
    } else if ((value = FlagValue(argv[i], "--sku")) != nullptr) {
      sku = value;
    } else if ((value = FlagValue(argv[i], "--sku_auth")) != nullptr) {
      sku_auth = value;
    } else {
      PrintUsage(argv[0]);
      return kSetupError;
    }
  }
  const bool run_session = sku[0] != '\0';

  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  SetUnhandledExceptionFilter(CrashFilter);

  std::printf("[ate_dll_smoke] dll=%s mtls=%d mlkem=%d mldsa=%d\n", dll_path,
              mtls, mlkem, mldsa);
  std::fflush(stdout);

  HMODULE dll = LoadLibraryA(dll_path);
  if (dll == nullptr) {
    std::printf("[ate_dll_smoke] LoadLibraryA(%s) failed: %lu\n", dll_path,
                GetLastError());
    return kSetupError;
  }
  auto create_client =
      reinterpret_cast<CreateClientFn>(GetProcAddress(dll, "CreateClient"));
  auto destroy_client =
      reinterpret_cast<DestroyClientFn>(GetProcAddress(dll, "DestroyClient"));
  auto init_session =
      reinterpret_cast<InitSessionFn>(GetProcAddress(dll, "InitSession"));
  auto close_session =
      reinterpret_cast<CloseSessionFn>(GetProcAddress(dll, "CloseSession"));
  if (create_client == nullptr || destroy_client == nullptr ||
      init_session == nullptr || close_session == nullptr) {
    std::printf("[ate_dll_smoke] GetProcAddress failed: %lu\n", GetLastError());
    return kSetupError;
  }

  client_options_t options;
  std::memset(&options, 0, sizeof(options));
  options.pa_target = target;
  options.load_balancing_policy = "";
  options.pem_cert_chain = cert;
  options.pem_private_key = key;
  options.pem_root_certs = ca;
  options.sku_tokens = "";
  options.enable_mtls = mtls;
  options.enable_mlkem_tls = mlkem;
  options.enable_mldsa_tls = mldsa;

  std::printf("[ate_dll_smoke] calling CreateClient...\n");
  std::fflush(stdout);

  ate_client_ptr client = nullptr;
  int result = create_client(&client, &options);
  std::printf("[ate_dll_smoke] CreateClient returned %d (client=%p)\n", result,
              reinterpret_cast<void *>(client));
  std::fflush(stdout);

  // Exercising a session requires a live Provisioning Appliance: this is what
  // actually drives the mTLS handshake and a round-trip RPC.
  if (result == 0 && run_session) {
    std::printf("[ate_dll_smoke] calling InitSession(sku=%s)...\n", sku);
    std::fflush(stdout);
    result = init_session(client, sku, sku_auth);
    std::printf("[ate_dll_smoke] InitSession returned %d\n", result);
    std::fflush(stdout);

    if (result == 0) {
      int close_result = close_session(client);
      std::printf("[ate_dll_smoke] CloseSession returned %d\n", close_result);
      std::fflush(stdout);
      if (close_result != 0) {
        result = close_result;
      }
    }
  }

  if (client != nullptr) {
    destroy_client(client);
  }
  std::printf("[ate_dll_smoke] DONE\n");
  std::fflush(stdout);
  return result == 0 ? 0 : 1;
}
