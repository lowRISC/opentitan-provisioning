{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf types optional optionals;

  cfg = config.services.opentitan-provisioning.spm;

  tlsOpts = {
    options = {
      enable = mkEnableOption "mTLS secure channel for SPM server";

      enableMlkemTls = mkOption {
        type = types.bool;
        default = true;
        description = "Enable MLKEM TLS configuration.";
      };

      enableMldsaTls = mkOption {
        type = types.bool;
        default = true;
        description = "Enable MLDSA certificate verification TLS configuration.";
      };

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

      caCertFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to PEM encoding of CA root certificates.";
      };
    };
  };

  hsmOpts = {
    options = {
      soPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to the PKCS#11 .so library used to interface to the HSM (e.g. SoftHSM or hardware HSM).";
      };

      pwFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "File path containing the HSM's password/PIN.";
      };
    };
  };

  args = [
    "-port=${toString cfg.port}"
  ]
  ++ optional (cfg.configDir != null) "-spm_config_dir=${toString cfg.configDir}"
  ++ optional (cfg.authConfig != null) "-spm_auth_config=${toString cfg.authConfig}"
  ++ optional (cfg.hsm.soPath != null) "-hsm_so=${toString cfg.hsm.soPath}"
  ++ optional (cfg.hsm.pwFile != null) "-hsm_pw=${toString cfg.hsm.pwFile}"
  ++ optional cfg.tls.enable "-enable_tls"
  ++ optional cfg.tls.enableMlkemTls "-enable_mlkem_tls"
  ++ optional cfg.tls.enableMldsaTls "-enable_mldsa_tls"
  ++ optional (cfg.tls.certFile != null) "-service_cert=${toString cfg.tls.certFile}"
  ++ optional (cfg.tls.keyFile != null) "-service_key=${toString cfg.tls.keyFile}"
  ++ optional (cfg.tls.caCertFile != null) "-ca_root_certs=${toString cfg.tls.caCertFile}"
  ++ cfg.extraArgs;

in {
  options.services.opentitan-provisioning.spm = {
    enable = mkEnableOption "OpenTitan Security Policy Manager (SPM) service";

    package = mkOption {
      type = types.package;
      defaultText = lib.literalExpression "pkgs.opentitan-provisioning.spm_server";
      description = "The spm_server package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 5000;
      description = "Port for the SPM server to listen on.";
    };

    configDir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the SPM configuration directory.";
    };

    authConfig = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "File path to the SPM Auth configuration file (relative to configDir).";
    };

    hsm = mkOption {
      type = types.submodule hsmOpts;
      default = {};
      description = "HSM / PKCS#11 configuration options.";
    };

    tls = mkOption {
      type = types.submodule tlsOpts;
      default = {};
      description = "TLS / mTLS configuration.";
    };

    user = mkOption {
      type = types.str;
      default = "opentitan";
      description = "User account under which the SPM service runs.";
    };

    group = mkOption {
      type = types.str;
      default = "opentitan";
      description = "Group under which the SPM service runs.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional command-line arguments to pass to spm_server.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.opentitan-spm = {
      description = "OpenTitan Security Policy Manager (SPM) Service";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/spm_server ${lib.escapeShellArgs args}";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "opentitan";
        Restart = "always";
        RestartSec = "5s";
      };
    };
  };
}
