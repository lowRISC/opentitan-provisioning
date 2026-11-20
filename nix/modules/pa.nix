{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf types optional optionals;

  cfg = config.services.opentitan-provisioning.pa;

  tlsOpts = {
    options = {
      enable = mkEnableOption "mTLS secure channel for PA server";

      certFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to PEM encoding of server certificate chain.";
      };

      keyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to PEM encoding of server private key.";
      };

      fallbackCertFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Optional path to PEM classical fallback certificate chain; setting this enables mixed PQ/classical TLS migration mode.";
      };

      fallbackKeyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Optional path to PEM classical fallback private key; setting this enables mixed PQ/classical TLS migration mode.";
      };

      caCertFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to PEM encoding of CA root certificates.";
      };
    };
  };

  args = [
    "-port=${toString cfg.port}"
    "-spm_address=${cfg.spmAddress}"
  ]
  ++ optional cfg.enableRegistry "-enable_registry"
  ++ optional (cfg.registryAddress != null) "-registry_address=${cfg.registryAddress}"
  ++ optional cfg.tls.enable "-enable_tls"
  ++ optional (cfg.tls.certFile != null) "-service_cert=${toString cfg.tls.certFile}"
  ++ optional (cfg.tls.keyFile != null) "-service_key=${toString cfg.tls.keyFile}"
  ++ optional (cfg.tls.fallbackCertFile != null) "-fallback_service_cert=${toString cfg.tls.fallbackCertFile}"
  ++ optional (cfg.tls.fallbackKeyFile != null) "-fallback_service_key=${toString cfg.tls.fallbackKeyFile}"
  ++ optional (cfg.tls.caCertFile != null) "-ca_root_certs=${toString cfg.tls.caCertFile}"
  ++ cfg.extraArgs;

in {
  options.services.opentitan-provisioning.pa = {
    enable = mkEnableOption "OpenTitan Provisioning Appliance (PA) service";

    package = mkOption {
      type = types.package;
      defaultText = lib.literalExpression "pkgs.opentitan-provisioning.pa_server";
      description = "The pa_server package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 5003;
      description = "Port for the PA server to listen on.";
    };

    spmAddress = mkOption {
      type = types.str;
      default = "127.0.0.1:5000";
      description = "Address (host:port) of the Security Policy Manager (SPM) service.";
    };

    enableRegistry = mkOption {
      type = types.bool;
      default = true;
      description = "Enable connectivity to the Registry (Proxy Buffer) server.";
    };

    registryAddress = mkOption {
      type = types.nullOr types.str;
      default = "127.0.0.1:5001";
      description = "Address (host:port) of the Registry / Proxy Buffer service.";
    };

    tls = mkOption {
      type = types.submodule tlsOpts;
      default = {};
      description = "TLS / mTLS configuration.";
    };

    user = mkOption {
      type = types.str;
      default = "opentitan";
      description = "User account under which the PA service runs.";
    };

    group = mkOption {
      type = types.str;
      default = "opentitan";
      description = "Group under which the PA service runs.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional command-line arguments to pass to pa_server.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = (cfg.tls.fallbackCertFile == null) == (cfg.tls.fallbackKeyFile == null);
        message = "services.opentitan-provisioning.pa.tls.fallbackCertFile and fallbackKeyFile must be set together.";
      }
    ];

    systemd.services.opentitan-pa = {
      description = "OpenTitan Provisioning Appliance (PA) Service";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ]
        ++ optional config.services.opentitan-provisioning.spm.enable "opentitan-spm.service"
        ++ optional config.services.opentitan-provisioning.pb.enable "opentitan-pb.service";

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/pa_server ${lib.escapeShellArgs args}";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "opentitan";
        Restart = "always";
        RestartSec = "5s";
      };
    };
  };
}
