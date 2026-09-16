# Copyright lowRISC contributors (OpenTitan project).
# SPDX-License-Identifier: Apache-2.0
#
# Nix derivation for the Thales Luna HSM Client (Linux, x86_64).
#
# ==============================================================================
# Downloading & Installing the Vendor Tarball
# ==============================================================================
# Because the Thales Luna HSM Client software is proprietary and subject to
# vendor export/license controls, the tarball cannot be committed to this
# repository or fetched from a public mirror.
#
# 1. Download the tarball from the Thales Customer Support Portal:
#    - Portal URL: https://supportportal.thalesgroup.com/
#    - Product:    Luna Network HSM Client 10.9.4 for Linux (64-bit)
#    - Part No:    610-000397-020
#    - Filename:   610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar
#    - SHA-256:    20984297cb8c30cac2e7a863a2a89e07ff385c467c9ce678e68e3668ef1ce6df
#    - Release notes / docs:
#      https://thalesdocs.com/gphsm/luna/10.9/docs/network/Content/crn/Luna/crn_luna_hsm_10.9.htm
#
# 2. Install the tarball on the NixOS host machine using ONE of the following:
#
#    Option A: Place in host directory (recommended for appliances)
#      Copy the tarball to `/var/lib/luna/610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar`
#      and build/switch with `--impure`:
#        sudo mkdir -p /var/lib/luna
#        sudo cp 610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar /var/lib/luna/
#        sudo nixos-rebuild switch --flake .#provisioning-appliance-luna --impure
#
#    Option B: Pre-seed the Nix store (for pure flake builds without `--impure`)
#      Add the tarball directly to `/nix/store` once:
#        nix-store --add-fixed sha256 610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar
#      After this, pure flake commands work without `--impure`:
#        sudo nixos-rebuild switch --flake .#provisioning-appliance-luna
#
# ==============================================================================
# Packaging Notes
# ==============================================================================
# The vendor installer (install.sh) shells out to `rpm -ivh` and hardcodes the
# FHS path /usr/safenet/lunaclient, neither of which works on NixOS. Instead we
# unpack the RPM payloads directly and let autoPatchelfHook rewrite the ELF
# interpreter and RPATHs against nixpkgs glibc/libstdc++/libcap.
{ lib
, stdenv
, requireFile
, autoPatchelfHook
, makeWrapper
, rpmextract
, libcap
, tarballPath ? "/var/lib/luna/610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar"
, sha256 ? "20984297cb8c30cac2e7a863a2a89e07ff385c467c9ce678e68e3668ef1ce6df"
}:

stdenv.mkDerivation rec {
  pname = "luna-hsm-client";
  version = "10.9.4-122";

  src =
    if builtins.pathExists tarballPath then
      builtins.fetchurl {
        url = "file://${toString tarballPath}";
        inherit sha256;
      }
    else
      requireFile {
        name = baseNameOf tarballPath;
        inherit sha256;
        message = ''
          The Thales Luna HSM Client tarball was not found in /nix/store or at ${toString tarballPath}.

          1. Download `610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar` from the
             Thales Customer Support Portal: https://supportportal.thalesgroup.com/
             (Search Part Number `610-000397-020` / Luna HSM Client 10.9.4 for Linux)

          2. Either place the tarball at ${toString tarballPath} and run with `--impure`:
               sudo mkdir -p /var/lib/luna
               sudo cp 610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar ${toString tarballPath}

             OR add it directly to the Nix store for pure builds:
               nix-store --add-fixed sha256 610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar
        '';
      };

  nativeBuildInputs = [ autoPatchelfHook makeWrapper rpmextract ];
  buildInputs = [ stdenv.cc.cc.lib libcap ];

  # Vendor binaries are shipped unstripped; leave them alone.
  dontStrip = true;
  dontConfigure = true;
  dontBuild = true;

  # Packages needed to drive a network Luna HSM as a client.
  lunaPackages = [
    "libcryptoki"   # libCryptoki2_64.so + default Chrystoki.conf
    "libshim"       # libshim.so
    "cklog"         # libcklog2.so (PKCS#11 call logging)
    "lunacm"        # lunacm
    "vtl"           # vtl + openssl.cnf
    "ckdemo"        # ckdemo
    "lunacmu"       # cmu
    "salogin"       # salogin (persistent app-id session)
    "configurator"  # configurator
    "multitoken"    # multitoken
  ];

  unpackPhase = ''
    runHook preUnpack
    tar xf $src
    cd LunaClient_${version}_Linux/64
    runHook postUnpack
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p unpacked
    for pkg in $lunaPackages; do
      echo "extracting $pkg ..."
      ( cd unpacked && rpmextract ../$pkg-${version}.x86_64.rpm )
    done

    chmod -R u+rwX unpacked

    mkdir -p $out/bin $out/lib $out/share/luna
    cp -r unpacked/usr/safenet/lunaclient/lib/. $out/lib/
    cp -r unpacked/usr/safenet/lunaclient/bin/. $out/bin/

    if [ -f $out/bin/openssl.cnf ]; then
      mv $out/bin/openssl.cnf $out/share/luna/openssl.cnf
    fi

    cp unpacked/etc/Chrystoki.conf $out/share/luna/Chrystoki.conf.template

    runHook postInstall
  '';

  postFixup = ''
    for bin in $out/bin/*; do
      [ -f "$bin" ] && [ -x "$bin" ] || continue
      wrapProgram "$bin" \
        --inherit-argv0 \
        --set-default ChrystokiConfigurationPath /var/lib/luna
    done
  '';

  meta = with lib; {
    description = "Thales Luna Network HSM client (PKCS#11 library and tools)";
    homepage = "https://thalesdocs.com/gphsm/luna/10.9/docs/network/Content/home.htm";
    license = licenses.unfree;
    platforms = [ "x86_64-linux" ];
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
  };
}
