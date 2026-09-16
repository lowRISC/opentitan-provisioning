# Copyright lowRISC contributors (OpenTitan project).
# SPDX-License-Identifier: Apache-2.0
#
# NixOS profile: Thales Luna Network HSM configuration for OpenTitan Provisioning.
# Mirrors `softhsm.nix` for production / lab hardware HSM deployments.
#
# Prerequisite: The proprietary Thales Luna HSM Client tarball
# (`610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar`) must be downloaded
# from the Thales Customer Support Portal (https://supportportal.thalesgroup.com/)
# and placed at `/var/lib/luna/610-000397-020_SW_Linux_Luna_Client_V10.9.4_RevA.tar`
# (or added via `nix-store --add-fixed sha256 ...`). See `../packages/luna-hsm-client.nix`
# for detailed download and installation instructions.
{ config, lib, pkgs, ... }:

let
  lunaClient = pkgs.opentitan-provisioning.luna-hsm-client or (pkgs.callPackage ../packages/luna-hsm-client.nix {});
  defaultPinFile = pkgs.writeText "default-hsm-pin" "cryptoki";
  defaultSkuAuth = ../../config/spm/sku_auth.yml.tmpl;
  stateDir = "/var/lib/luna";
  clientName = config.networking.hostName or "ClientName";

  # Seed Chrystoki.conf once; `vtl addServer` modifies it in-place afterwards.
  chrystokiSeed = pkgs.writeText "Chrystoki.conf" ''
    Chrystoki2 = {
      LibUNIX64 = ${lunaClient}/lib/libCryptoki2_64.so;
    }

    Luna = {
      DefaultTimeOut = 500000;
      PEDTimeout1 = 100000;
      PEDTimeout2 = 200000;
      PEDTimeout3 = 20000;
      KeypairGenTimeOut = 2700000;
      CloningCommandTimeOut = 300000;
      CommandTimeOutPedSet = 720000;
    }

    CardReader = {
      RemoteCommand = 1;
    }

    Misc = {
      PE1746Enabled = 0;
      ValidateHost = 0;
      ToolsDir = ${lunaClient}/bin;
    }

    LunaSA Client = {
      NetClient = 1;
      ReceiveTimeout = 20000;
      SSLConfigFile = ${lunaClient}/share/luna/openssl.cnf;
      ClientCertFile = ${stateDir}/cert/client/${clientName}.pem;
      ClientPrivKeyFile = ${stateDir}/cert/client/${clientName}Key.pem;
      ServerCAFile = ${stateDir}/cert/server/CAFile.pem;
    }
  '';
in
{
  nixpkgs.config.allowUnfreePredicate = pkg:
    builtins.elem (lib.getName pkg) [ "luna-hsm-client" "610" ];

  # Configure SPM to use Thales Luna PKCS#11 module and default PIN file
  services.opentitan-provisioning.spm.hsm = {
    soPath = lib.mkDefault "${lunaClient}/lib/libCryptoki2_64.so";
    pwFile = lib.mkDefault "/var/lib/opentitan/hsm_pin";
  };

  environment.variables = {
    ChrystokiConfigurationPath = lib.mkDefault stateDir;
    OPENSSL_ENGINES = lib.mkDefault "${pkgs.libp11}/lib/engines";
  };

  systemd.services.opentitan-spm = {
    environment = {
      ChrystokiConfigurationPath = lib.mkDefault stateDir;
      OPENSSL_ENGINES = lib.mkDefault "${pkgs.libp11}/lib/engines";
      SOFTHSM2_CONF = lib.mkForce "";
    };
    serviceConfig.SupplementaryGroups = [ "hsmusers" ];
  };

  users.groups.hsmusers = {};
  users.users.opentitan.extraGroups = [ "hsmusers" ];
  users.users.admin.extraGroups = [ "hsmusers" ];

  # Ensure Luna state/certificate directories and default SPM config files exist
  systemd.tmpfiles.rules = [
    "d ${stateDir}             0750 root hsmusers -"
    "d ${stateDir}/cert        0750 root hsmusers -"
    "d ${stateDir}/cert/client 0770 root hsmusers -"
    "d ${stateDir}/cert/server 0770 root hsmusers -"
    "C ${stateDir}/Chrystoki.conf 0660 root hsmusers - ${chrystokiSeed}"
    "C /var/lib/opentitan/hsm_pin 0600 opentitan opentitan - ${defaultPinFile}"
    "C /var/lib/opentitan/config/sku_auth.yml 0640 opentitan opentitan - ${defaultSkuAuth}"
  ];

  environment.systemPackages = with pkgs; [
    lunaClient
    libp11
    openssl
    gettext
  ];
}
