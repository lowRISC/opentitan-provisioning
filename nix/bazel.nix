{ pkgs, bcr, src }:

let
  buildBazel8Derivation = pkgs.callPackage "${pkgs.path}/pkgs/by-name/ba/bazel_8/build-support/bazelDerivation.nix" {};

  # Deterministic Bazel vendor Fixed-Output Derivation (FOD) SHA-256 hash.
  # Shared across all targets (bazelDepsCache, services, and testBinaries).
  # Because vendorRawSource excludes code files under src/, editing Go/Rust/C++
  # source files in src/ NEVER invalidates this FOD or bazelDepsCache.
  #
  # When MODULE.bazel, go.mod, Cargo.lock, or third_party patches change:
  # 1. Temporarily replace sha256Hash with pkgs.lib.fakeHash (or "").
  # 2. Run: nix build path:.#all
  # 3. Copy the computed SHA-256 mismatch hash back here.
  sha256Hash = "sha256-0k8kErJBVYKmQXGPEdFUFJQVnKCUIx92KPXdkBqBf+Q=";

  # Full source tree for Stage 3 builds (services and testBinaries).
  rawSource = pkgs.lib.cleanSourceWith {
    inherit src;
    filter = path: type:
      let base = baseNameOf path;
      in !(
        base == "result" ||
        base == ".git" ||
        base == ".github" ||
        base == ".gitignore" ||
        base == "docs" ||
        base == "README.md" ||
        base == "nix" ||
        base == "nix-logs" ||
        base == "flake.lock" ||
        pkgs.lib.hasPrefix "bazel-" base ||
        pkgs.lib.hasSuffix ".nix" base ||
        pkgs.lib.hasSuffix ".log" base
      );
  };

  # Filtered source tree for Stage 1 (bazel vendor) and Stage 2.5 (bazelDepsCache).
  # Excludes implementation code files (.go, .c, .cc, .cpp, .h, .rs) under src/ at Nix
  # evaluation time so that editing application code NEVER triggers re-evaluation or
  # rebuilding of vendor dependencies or external C++/Rust/Go caches.
  vendorRawSource = pkgs.lib.cleanSourceWith {
    inherit src;
    filter = path: type:
      let
        base = baseNameOf path;
        rel = pkgs.lib.removePrefix (toString src + "/") (toString path);
        inSrc = pkgs.lib.hasPrefix "src/" rel;
        isCodeFile =
          pkgs.lib.hasSuffix ".go" base ||
          pkgs.lib.hasSuffix ".c" base ||
          pkgs.lib.hasSuffix ".cc" base ||
          pkgs.lib.hasSuffix ".cpp" base ||
          pkgs.lib.hasSuffix ".h" base ||
          pkgs.lib.hasSuffix ".rs" base;
      in !(
        base == "result" ||
        base == ".git" ||
        base == ".github" ||
        base == ".gitignore" ||
        base == "docs" ||
        base == "README.md" ||
        base == "nix" ||
        base == "nix-logs" ||
        base == "flake.lock" ||
        pkgs.lib.hasPrefix "bazel-" base ||
        pkgs.lib.hasSuffix ".nix" base ||
        pkgs.lib.hasSuffix ".log" base ||
        (inSrc && type != "directory" && isCodeFile)
      );
  };

  commonSourcePatch = ''
    chmod -R +w $out
    cd $out
    rm -f .bazelversion MODULE.bazel.lock
    sed -i 's|register_toolchains("@llvm_toolchain_host//:all")|# register_toolchains("@llvm_toolchain_host//:all")|g' MODULE.bazel
    sed -i 's|"OPENSSL_STATIC": "1"|"OPENSSL_STATIC": "0"|g' MODULE.bazel
    cat << 'EOF' > util/get_workspace_status.sh
#!/bin/sh
echo "BUILD_SCM_REVISION 0.1.0"
echo "BUILD_GIT_VERSION 0.1.0"
echo "BUILD_SCM_STATUS clean"
EOF
    chmod +x util/get_workspace_status.sh
    cat << 'EOF' >> .bazelrc
build --spawn_strategy=standalone
build --genrule_strategy=standalone
EOF
  '';

  cleanedSource = pkgs.runCommand "opentitan-provisioning-src" {} ''
    cp -r ${rawSource} $out
    ${commonSourcePatch}
  '';

  # Creates empty 0-byte stub files for any .go/.c/.cc/.h/.rs files referenced in
  # src/**/BUILD.bazel so Bazel's loading phase succeeds without depending on file contents.
  cleanedVendorSource = pkgs.runCommand "opentitan-provisioning-vendor-src" {} ''
    cp -r ${vendorRawSource} $out
    ${commonSourcePatch}
    ${pkgs.python3}/bin/python3 -c '
import os, re

for root, dirs, files in os.walk("src"):
    if "BUILD.bazel" in files:
        with open(os.path.join(root, "BUILD.bazel")) as f:
            content = f.read()
        for m in re.findall(r"\"([^\"]+\.(?:go|c|cc|cpp|h|rs))\"", content):
            p = os.path.join(root, m)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                open(p, "w").close()
'
  '';

  cargoBazelUnpatched = pkgs.fetchurl {
    url = "https://github.com/bazelbuild/rules_rust/releases/download/0.59.2/cargo-bazel-x86_64-unknown-linux-gnu";
    sha256 = "a32679e1adab2e7c6867c214cc30ccfedcc508484a3999645e8ed65ef10b7df4";
  };

  actionPath = pkgs.lib.makeBinPath [
    pkgs.stdenv.cc
    pkgs.stdenv.cc.bintools
    pkgs.bash
    pkgs.coreutils
    pkgs.envsubst
    pkgs.findutils
    pkgs.gawk
    pkgs.gnugrep
    pkgs.gnused
    pkgs.gnutar
    pkgs.gzip
    pkgs.pkg-config.pkg-config
    pkgs.python3
  ];

  # Python script to patch shebangs (/usr/bin/env python*, /usr/bin/env bash, #!/bin/bash)
  # and inject Nix OpenSSL / pkg-config paths into rules_rust cargo_build_script.bzl during Stage 2.
  patchVendorScript = pkgs.writeText "patch-vendor-shebangs.py" ''
    import os
    import subprocess
    import sys

    python3_bin = sys.argv[1]
    bash_bin = sys.argv[2]
    action_path = sys.argv[3]
    pkg_config_bin = sys.argv[4]
    openssl_dev = sys.argv[5]
    openssl_lib = sys.argv[6]
    openssl_inc = sys.argv[7]
    vendor_src = sys.argv[8]
    dst_dir = sys.argv[9]

    res = subprocess.run(
        [
            "${pkgs.gnugrep}/bin/grep",
            "-rl",
            "--include=*.bzl",
            "--include=*.py",
            "--include=*.sh",
            "--include=*.txt",
            "-E",
            "/usr/bin/env|#!/bin/bash",
            vendor_src,
        ],
        capture_output=True,
        text=True,
    )

    count = 0
    for src_path in res.stdout.splitlines():
        if not src_path or not os.path.exists(src_path):
            continue
        rel_path = os.path.relpath(src_path, vendor_src)
        dst_path = os.path.join(dst_dir, rel_path)
        if not os.path.lexists(dst_path):
            continue
        with open(src_path, "rb") as f:
            data = f.read()
        new_data = (
            data
            .replace(b"/usr/bin/env python3", python3_bin.encode())
            .replace(b"/usr/bin/env python", python3_bin.encode())
            .replace(b"/usr/bin/env bash", bash_bin.encode())
            .replace(b"#!/bin/bash", b"#!" + bash_bin.encode())
        )
        if new_data != data:
            if os.path.islink(dst_path) or os.path.exists(dst_path):
                os.unlink(dst_path)
            with open(dst_path, "wb") as f:
                f.write(new_data)
            os.chmod(dst_path, 0o755)
            count += 1

    # Inject Nix pkg-config and OpenSSL paths into rules_rust cargo_build_script.bzl
    cbs_rel = "rules_rust+/cargo/private/cargo_build_script.bzl"
    cbs_src = os.path.join(vendor_src, cbs_rel)
    cbs_dst = os.path.join(dst_dir, cbs_rel)
    if os.path.exists(cbs_src):
        with open(cbs_src, "rb") as f:
            cbs_data = f.read()
        target = b"    ctx.actions.run(\n        executable = ctx.executable._cargo_build_script_runner,"
        replacement = (
            f'    env["PATH"] = "{action_path}:" + env.get("PATH", "")\n'
            f'    env["PKG_CONFIG"] = "{pkg_config_bin}"\n'
            f'    env["OPENSSL_DIR"] = "{openssl_dev}"\n'
            f'    env["OPENSSL_LIB_DIR"] = "{openssl_lib}"\n'
            f'    env["OPENSSL_INCLUDE_DIR"] = "{openssl_inc}"\n'
        ).encode() + target
        if target in cbs_data:
            if os.path.islink(cbs_dst) or os.path.exists(cbs_dst):
                os.unlink(cbs_dst)
            with open(cbs_dst, "wb") as f:
                f.write(cbs_data.replace(target, replacement, 1))
            os.chmod(cbs_dst, 0o755)
            print("Patched cargo_build_script.bzl with Nix PKG_CONFIG and OPENSSL env vars")

    print(f"Patched {count} files in {dst_dir}")
  '';

  # Python script to strip /nix/store references from vendor_dir at the end of Stage 1 (FOD).
  stripVendorScript = pkgs.writeText "strip-vendor-refs.py" ''
    import re
    import sys

    path = sys.argv[1]
    pattern = re.compile(b"/nix/store/[a-z0-9]{32}")
    repl = b"/no-such-path/00000000000000000000000000000"
    with open(path, "rb") as f:
        data = f.read()
    new_data = pattern.sub(repl, data)
    if new_data != data:
        with open(path, "wb") as f:
            f.write(new_data)
  '';

  stripVendorRefsHook = pkgs.makeSetupHook {
    name = "strip-vendor-refs-hook";
  } (pkgs.writeScript "strip-vendor-refs.sh" ''
    stripVendorRefs() {
      if [ "$name" = "bazelVendorDepsStage1" ] && [ -d vendor_dir ]; then
        echo "Cleaning non-deterministic artifacts and /nix/store references from vendor_dir for FOD..."
        chmod -R u+w vendor_dir 2>/dev/null || true

        # 1. Remove Stage 1 Go build cache & go.env (which embed random mktemp HOME paths and CPU cache keys)
        rm -rf vendor_dir/gazelle++non_module_deps+bazel_gazelle_go_repository_cache/gocache
        if [ -f vendor_dir/gazelle++non_module_deps+bazel_gazelle_go_repository_cache/go.env ]; then
          : > vendor_dir/gazelle++non_module_deps+bazel_gazelle_go_repository_cache/go.env
        fi

        # 2. Replace Stage-1-compiled Gazelle helper ELF binaries with deterministic stubs
        # (Unused in Stage 3 because all @gazelle++go_deps+* repos are already generated & pinned)
        for bin in vendor_dir/gazelle++non_module_deps+bazel_gazelle_go_repository_tools/bin/*; do
          if [ -f "$bin" ] && [ ! -L "$bin" ]; then
            printf '#!/bin/sh\nexit 0\n' > "$bin"
            chmod +x "$bin"
          fi
        done

        # 3. Remove all .marker files (unused in Stage 3 when pinned in VENDOR.bazel, and they record host env/path hashes)
        find vendor_dir -maxdepth 1 -name "*.marker" -delete

        # 4. Write deterministic sorted VENDOR.bazel pinning all vendored repositories
        find vendor_dir -mindepth 1 -maxdepth 1 -type d -printf 'pin("@@%P")\n' | LC_ALL=C sort > vendor_dir/VENDOR.bazel

        # 5. Strip /nix/store references from ELF binaries and text files
        for f in $(${pkgs.gnugrep}/bin/grep -rl "/nix/store/" vendor_dir 2>/dev/null || true); do
          if [ -f "$f" ] && [ ! -L "$f" ]; then
            if ${pkgs.patchelf}/bin/patchelf --print-interpreter "$f" >/dev/null 2>&1; then
              ${pkgs.patchelf}/bin/patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --set-rpath '$ORIGIN/../lib' "$f" 2>/dev/null || true
            elif ${pkgs.patchelf}/bin/patchelf --print-rpath "$f" >/dev/null 2>&1; then
              ${pkgs.patchelf}/bin/patchelf --set-rpath '$ORIGIN' "$f" 2>/dev/null || true
            fi
            ${pkgs.python3}/bin/python3 ${stripVendorScript} "$f"
          fi
        done
      fi
    }
    postBuildHooks+=(stripVendorRefs)
  '');

  commonStartupArgs = [
    "--output_user_root=/build/bazel_root"
  ];

  commonEnv = {
    NIX_DYNAMIC_LINKER = "${pkgs.stdenv.cc.bintools.dynamicLinker}";
    NIX_PATCHELF = "${pkgs.patchelf}/bin/patchelf";
    NIX_PYTHON3 = "${pkgs.python3}/bin/python3";
    NIX_BASH = "${pkgs.bash}/bin/bash";
    NIX_LIB_PATH = "${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]}";
    CARGO_BAZEL_GENERATOR_URL = "file://${cargoBazelUnpatched}";
    CARGO_BAZEL_GENERATOR_SHA256 = "a32679e1adab2e7c6867c214cc30ccfedcc508484a3999645e8ed65ef10b7df4";
  };

  commonCommandArgs = [
    "--define=env=dev"
    "--define=pq=true"
    "--@lowrisc_opentitan_head//third_party/rust:openssl_pkg_config_path=${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.systemd.dev}/lib/pkgconfig"
    "--action_env=PATH=${actionPath}:/bin:/usr/bin"
    "--host_action_env=PATH=${actionPath}:/bin:/usr/bin"
    "--action_env=PKG_CONFIG=${pkgs.pkg-config.pkg-config}/bin/pkg-config"
    "--host_action_env=PKG_CONFIG=${pkgs.pkg-config.pkg-config}/bin/pkg-config"
    "--action_env=PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.systemd.dev}/lib/pkgconfig"
    "--host_action_env=PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.systemd.dev}/lib/pkgconfig"
    "--action_env=OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib"
    "--action_env=OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include"
    "--host_action_env=OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib"
    "--host_action_env=OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include"
  ];

  commonNativeBuildInputs = with pkgs; [
    pkg-config
    patchelf
    envsubst
  ];

  commonBuildInputs = with pkgs; [
    stdenv.cc.cc.lib
    ncurses5
    zlib
    openssl
    systemd
  ];

  autoPatchelfIgnoreMissingDeps = [
    "libtiff.so.6"
    "libstdc++.so.6"
    "libgcc_s.so.1"
    "libtinfo.so.5"
    "libtinfo.so.6"
    "libcrypt.so.1"
  ];

  # Stage 1: Deterministic Fixed-Output Derivation (FOD) produced by `bazel vendor`.
  bazelVendorStage1 = buildBazel8Derivation {
    name = "bazelVendorDepsStage1";
    version = "0.1.0";
    src = cleanedVendorSource;
    sourceRoot = null;
    registry = "${bcr}";
    bazelRepoCache = null;
    bazelVendorDeps = null;
    bazel = pkgs.bazel_8;
    startupArgs = commonStartupArgs;
    serverJavabase = null;
    command = "vendor";
    dontFixup = true;
    outputHash = sha256Hash;
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
    env = commonEnv;
    commandArgs = [ "--vendor_dir=vendor_dir" ] ++ commonCommandArgs;
    targets = [
      "//src/pa:pa_server"
      "//src/spm:spm_server"
      "//src/proxy_buffer:pb_server"
      "//src/pa:loadtest"
      "//src/ate/test_programs:tls_test"
      "//src/spm/services/testutils:tbsgen"
      "@lowrisc_opentitan_head//sw/host/hsmtool"
      "//config:release"
    ];
    nativeBuildInputs = commonNativeBuildInputs ++ [ stripVendorRefsHook ];
    buildInputs = commonBuildInputs;
    bazelPreBuild = ''
      export HOME=/build/home
      export USER=nixbld
      mkdir -p $HOME vendor_dir
    '';
    bazelPostBuild = ''
      # remove symlinks pointing to build directory or HOME
      find vendor_dir -type l -lname "$HOME/*" -exec rm '{}' \;
      find vendor_dir -type l -lname "/build/*" -exec rm '{}' \;
      find vendor_dir -xtype l -exec rm '{}' \;
    '';
    installPhase = ''
      mkdir -p $out/vendor_dir
      cp -r --reflink=auto vendor_dir/* $out/vendor_dir
    '';
  };

  # Stage 2: Fast vendor preparation (~18 seconds instead of ~21 minutes).
  # Creates a lightweight symlink tree of Stage 1, patches shebangs + rules_rust once,
  # and materializes only executable/shared-library ELF files for autoPatchelf.
  sharedVendorDeps = pkgs.stdenv.mkDerivation {
    name = "bazelVendorDeps";
    dontUnpack = true;
    dontCheckForBrokenSymlinks = true;
    dontRewriteSymlinks = true;
    dontPatchShebangs = true;
    dontStrip = true;
    dontAutoPatchelf = true;
    nativeBuildInputs = [
      pkgs.autoPatchelfHook
      pkgs.lndir
    ];
    buildInputs = commonBuildInputs;
    inherit autoPatchelfIgnoreMissingDeps;
    installPhase = ''
      mkdir -p $out/vendor_dir
      ${pkgs.lndir}/bin/lndir -silent ${bazelVendorStage1}/vendor_dir $out/vendor_dir

      echo "Patching shebangs and rules_rust in vendor_dir..."
      ${pkgs.python3}/bin/python3 ${patchVendorScript} \
        "${pkgs.python3}/bin/python3" \
        "${pkgs.bash}/bin/bash" \
        "${actionPath}" \
        "${pkgs.pkg-config.pkg-config}/bin/pkg-config" \
        "${pkgs.openssl.dev}" \
        "${pkgs.openssl.out}/lib" \
        "${pkgs.openssl.dev}/include" \
        "${bazelVendorStage1}/vendor_dir" \
        "$out/vendor_dir"

      echo "Materializing ELF binaries in vendor_dir for autoPatchelf..."
      ${pkgs.python3}/bin/python3 -c '
import os, shutil

vdir = os.path.join(os.environ["out"], "vendor_dir")
elfs = []
so_dirs = set()
for root, dirs, files in os.walk(vdir):
    for f in files:
        p = os.path.join(root, f)
        if ".so" in f:
            so_dirs.add(root)
        if not os.path.islink(p):
            continue
        if not (".so" in f or os.access(p, os.X_OK)):
            continue
        target = os.path.realpath(p)
        if not os.path.isfile(target):
            continue
        try:
            with open(target, "rb") as fp:
                if fp.read(4) == b"\x7fELF":
                    os.unlink(p)
                    shutil.copy2(target, p)
                    os.chmod(p, 0o755)
                    elfs.append(p)
        except Exception:
            pass

with open("/build/elf_files.txt", "w") as out_f:
    for e in elfs:
        out_f.write(e + "\n")
with open("/build/so_dirs.txt", "w") as out_f:
    for d in sorted(so_dirs):
        out_f.write(d + "\n")
print(f"Materialized {len(elfs)} ELF binaries for autoPatchelf")
      '
    '';
    postFixup = ''
      mapfile -t extraAutoPatchelfLibs < /build/so_dirs.txt
      mapfile -t elf_files < /build/elf_files.txt
      if [ "''${#elf_files[@]}" -gt 0 ]; then
        autoPatchelf -- "''${elf_files[@]}"
      fi
    '';
  };

  # Stage 2.5: Pre-warmed Bazel disk cache & external binary derivation.
  # Built from cleanedVendorSource (which excludes code in src/), so this derivation
  # NEVER rebuilds when Go/Rust/C++ files in src/ are edited.
  # Pre-compiles @lowrisc_opentitan_head//sw/host/hsmtool (300+ Rust crates),
  # SQLite, gRPC, Protobuf, C++ Abseil, and all .proto generated targets.
  bazelDepsCache = buildBazel8Derivation {
    name = "opentitan-provisioning-bazel-deps-cache";
    version = "0.1.0";
    src = cleanedVendorSource;
    sourceRoot = null;
    registry = "${bcr}";
    bazelRepoCache = null;
    bazelVendorDeps = sharedVendorDeps;
    bazel = pkgs.bazel_8;
    startupArgs = commonStartupArgs;
    serverJavabase = null;
    command = "build";
    dontFixup = true;
    env = commonEnv;
    commandArgs = commonCommandArgs ++ [
      "--disk_cache=/build/disk_cache"
    ];
    targets = [
      "@lowrisc_opentitan_head//sw/host/hsmtool"
      "@org_modernc_sqlite//:sqlite"
      "@org_golang_google_grpc//:grpc"
      "@com_google_protobuf//:protoc"
      "//src/pa/proto:pa_go_pb"
      "//src/spm/proto:spm_go_pb"
      "//src/proxy_buffer/proto:proxy_buffer_go_pb"
    ];
    nativeBuildInputs = commonNativeBuildInputs;
    buildInputs = commonBuildInputs;
    bazelPreBuild = ''
      export HOME=/build/home
      export USER=nixbld
      mkdir -p $HOME /build/disk_cache
    '';
    installPhase = ''
      mkdir -p $out/bin
      cp bazel-bin/external/*lowrisc_opentitan_head*/sw/host/hsmtool/hsmtool $out/bin/hsmtool
      chmod -R u+w /build/disk_cache
      tar -cf $out/disk_cache.tar -C /build/disk_cache .
    '';
  };

  mkBazelBuild = { name, targets, installPhase }:
    buildBazel8Derivation {
      inherit name targets installPhase;
      version = "0.1.0";
      src = cleanedSource;
      sourceRoot = null;
      registry = "${bcr}";
      bazelRepoCache = null;
      bazelVendorDeps = sharedVendorDeps;
      bazel = pkgs.bazel_8;
      startupArgs = commonStartupArgs;
      serverJavabase = null;
      command = "build";
      env = commonEnv;
      commandArgs = commonCommandArgs ++ [
        "--disk_cache=/build/disk_cache"
      ];
      nativeBuildInputs = commonNativeBuildInputs;
      buildInputs = commonBuildInputs;
      bazelPreBuild = ''
        export HOME=/build/home
        export USER=nixbld
        mkdir -p $HOME /build/disk_cache
        tar --no-same-owner --no-same-permissions -xf ${bazelDepsCache}/disk_cache.tar -C /build/disk_cache
        chmod -R u+w /build/disk_cache
      '';
    };

  services = mkBazelBuild {
    name = "opentitan-provisioning-services";
    targets = [
      "//src/pa:pa_server"
      "//src/spm:spm_server"
      "//src/proxy_buffer:pb_server"
    ];
    installPhase = ''
      mkdir -p $out/bin
      cp bazel-bin/src/pa/pa_server_/pa_server $out/bin/pa_server
      cp bazel-bin/src/spm/spm_server_/spm_server $out/bin/spm_server
      cp bazel-bin/src/proxy_buffer/pb_server_/pb_server $out/bin/pb_server
    '';
  };

  mkSingleService = name:
    pkgs.runCommand name {
      meta.mainProgram = name;
    } ''
      mkdir -p $out/bin
      cp ${services}/bin/${name} $out/bin/${name}
    '';

  pa_server = mkSingleService "pa_server";
  spm_server = mkSingleService "spm_server";
  pb_server = mkSingleService "pb_server";

  testBinaries = mkBazelBuild {
    name = "opentitan-provisioning-test-binaries";
    targets = [
      "//src/pa:loadtest"
      "//src/ate/test_programs:tls_test"
      "//src/spm/services/testutils:tbsgen"
      "//config:release"
    ];
    installPhase = ''
      mkdir -p $out/bin $out/share/opentitan
      cp bazel-bin/src/pa/loadtest_/loadtest $out/bin/pa_loadtest
      cp bazel-bin/src/ate/test_programs/tls_test_/tls_test $out/bin/tls_test
      cp bazel-bin/src/spm/services/testutils/tbsgen_/tbsgen $out/bin/tbsgen
      cp ${bazelDepsCache}/bin/hsmtool $out/bin/hsmtool
      cp bazel-bin/config/config.tar.gz $out/share/opentitan/config.tar.gz
    '';
  };
in
{
  inherit pa_server spm_server pb_server services testBinaries bazelDepsCache;
}
