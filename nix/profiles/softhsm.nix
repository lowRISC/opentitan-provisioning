{ config, lib, pkgs, ... }:

let
  defaultPinFile = pkgs.writeText "default-hsm-pin" "cryptoki";
  defaultSkuAuth = ../../config/spm/sku_auth.yml.tmpl;
  softhsmOfflineConf = pkgs.writeText "softhsm2-offline.conf" ''
    directories.tokendir = /var/lib/opentitan/tokens-offline
    objectstore.backend = file
    objectstore.umask = 0077
    log.level = DEBUG
    slots.removable = false
    slots.mechanisms = ALL
    library.reset_on_fork = false
  '';
in
{
  # Configure SPM to use SoftHSM2 library and default PIN file
  services.opentitan-provisioning.spm.hsm = {
    soPath = lib.mkDefault "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
    pwFile = lib.mkDefault "/var/lib/opentitan/hsm_pin";
  };

  # Primary SoftHSM configuration (for SPM runtime token: spm-hsm)
  environment.etc."softhsm2.conf".text = lib.mkDefault ''
    directories.tokendir = /var/lib/opentitan/tokens
    objectstore.backend = file
    objectstore.umask = 0077
    log.level = DEBUG
    slots.removable = false
    slots.mechanisms = ALL
    library.reset_on_fork = false
  '';

  environment.variables = {
    SOFTHSM2_CONF = lib.mkDefault "/etc/softhsm2.conf";
    OPENSSL_ENGINES = lib.mkDefault "${pkgs.libp11}/lib/engines";
  };

  systemd.services.opentitan-spm.environment = {
    SOFTHSM2_CONF = lib.mkDefault "/etc/softhsm2.conf";
    OPENSSL_ENGINES = lib.mkDefault "${pkgs.libp11}/lib/engines";
  };

  # Ensure SoftHSM token directories and default config files exist
  systemd.tmpfiles.rules = [
    "d /var/lib/opentitan/tokens 0700 opentitan opentitan -"
    "d /var/lib/opentitan/tokens-offline 0700 opentitan opentitan -"
    "C /var/lib/opentitan/hsm_pin 0600 opentitan opentitan - ${defaultPinFile}"
    "C /var/lib/opentitan/config/sku_auth.yml 0640 opentitan opentitan - ${defaultSkuAuth}"
    "C /var/lib/opentitan/config/softhsm2-offline.conf 0640 opentitan opentitan - ${softhsmOfflineConf}"
  ];

  # Initialize SoftHSM tokens (spm-hsm & offline-hsm) and run SKU token_init if available
  systemd.services.opentitan-hsm-init = lib.mkIf config.services.opentitan-provisioning.spm.enable {
    description = "Initialize SoftHSM tokens and SKU keys for OpenTitan SPM";
    wantedBy = [ "opentitan-spm.service" ];
    before = [ "opentitan-spm.service" ];
    path = with pkgs; [
      bash
      coreutils
      findutils
      gnused
      gnutar
      gzip
      xz
      softhsm
      openssl
      libp11
      gettext
    ];
    serviceConfig = {
      Type = "oneshot";
      User = "opentitan";
      Group = "opentitan";
      Environment = [
        "SOFTHSM2_CONF=/etc/softhsm2.conf"
        "OPENSSL_ENGINES=${pkgs.libp11}/lib/engines"
      ];
      ExecStart = pkgs.writeShellScript "init-softhsm-tokens" ''
        set -e

        # 1. Initialize spm-hsm token if empty
        if [ ! -d /var/lib/opentitan/tokens ] || [ -z "$(ls -A /var/lib/opentitan/tokens 2>/dev/null)" ]; then
          mkdir -p /var/lib/opentitan/tokens
          softhsm2-util --init-token --slot=0 --so-pin=cryptoki --label=spm-hsm --pin=cryptoki || true
        fi

        # 2. Initialize offline-hsm token if empty
        if [ ! -d /var/lib/opentitan/tokens-offline ] || [ -z "$(ls -A /var/lib/opentitan/tokens-offline 2>/dev/null)" ]; then
          mkdir -p /var/lib/opentitan/tokens-offline
          SOFTHSM2_CONF=/var/lib/opentitan/config/softhsm2-offline.conf \
            softhsm2-util --init-token --slot=0 --so-pin=cryptoki --label=offline-hsm --pin=cryptoki || true
        fi

        # 3. Unpack config.tar.gz and hsmutils.tar.xz if staged in /var/lib/opentitan/release
        if [ -f /var/lib/opentitan/release/config.tar.gz ] && [ ! -f /var/lib/opentitan/config/token_init.sh ]; then
          tar -xf /var/lib/opentitan/release/config.tar.gz -C /var/lib/opentitan
        fi
        if [ -f /var/lib/opentitan/release/hsmutils.tar.xz ] && [ ! -x /var/lib/opentitan/bin/hsmtool ]; then
          mkdir -p /var/lib/opentitan/bin
          tar -xf /var/lib/opentitan/release/hsmutils.tar.xz -C /var/lib/opentitan/bin
        fi

        # 4. Run token_init.sh for sival SKU if token_init.sh and hsmtool are present and sival cert is not yet generated
        if [ -f /var/lib/opentitan/config/token_init.sh ] && [ -x /var/lib/opentitan/bin/hsmtool ] && [ ! -f /var/lib/opentitan/config/spm/sku/sival/ca/sival-dice-key-p256-v0.priv.der ]; then
          cd /var/lib/opentitan/config
          find /var/lib/opentitan/config -type f \( -name "*.sh" -o -name "*.bash" \) -exec sed -i "s|^#!/bin/bash|#!/usr/bin/env bash|" {} +

          sed -i "s|export SOFTHSM2_CONF_SPM=.*|export SOFTHSM2_CONF_SPM=/etc/softhsm2.conf|" /var/lib/opentitan/config/env/dev/spm.env
          sed -i "s|export SOFTHSM2_CONF_OFFLINE=.*|export SOFTHSM2_CONF_OFFLINE=/var/lib/opentitan/config/softhsm2-offline.conf|" /var/lib/opentitan/config/env/dev/spm.env
          sed -i "s|export HSMTOOL_MODULE=.*|export HSMTOOL_MODULE=${pkgs.softhsm}/lib/softhsm/libsofthsm2.so|" /var/lib/opentitan/config/env/dev/spm.env

          export DEPLOY_ENV=dev
          export OPENTITAN_VAR_DIR=/var/lib/opentitan
          /var/lib/opentitan/config/token_init.sh --action spm-init
          /var/lib/opentitan/config/token_init.sh --action offline-common-init
          /var/lib/opentitan/config/token_init.sh --action offline-common-export
          /var/lib/opentitan/config/token_init.sh --action spm-sku-init --sku sival
          /var/lib/opentitan/config/token_init.sh --action offline-ca-root-certgen
          /var/lib/opentitan/config/token_init.sh --action spm-sku-csr --sku sival
          /var/lib/opentitan/config/token_init.sh --action offline-sku-certgen --sku sival
        fi

        # 5. Ensure SKU config files and directories are linked into /var/lib/opentitan/config for spm_server
        if [ -d /var/lib/opentitan/config/spm ]; then
          ln -sf /var/lib/opentitan/config/spm/sku_sival.yml /var/lib/opentitan/config/sku_sival.yml
          ln -sf /var/lib/opentitan/config/spm/sku_cr01.yml /var/lib/opentitan/config/sku_cr01.yml
          ln -sf /var/lib/opentitan/config/spm/sku_pi01.yml /var/lib/opentitan/config/sku_pi01.yml
          ln -sf /var/lib/opentitan/config/spm/sku_ti01.yml /var/lib/opentitan/config/sku_ti01.yml
          ln -sf /var/lib/opentitan/config/spm/sku /var/lib/opentitan/config/sku
        fi
      '';
    };
  };

  environment.systemPackages = with pkgs; [
    softhsm
    libp11
    openssl
    gettext
  ];
}
