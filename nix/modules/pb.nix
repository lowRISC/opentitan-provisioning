{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf types optional optionals;

  cfg = config.services.opentitan-provisioning.pb;

  tlsOpts = {
    options = {
      enable = mkEnableOption "mTLS secure channel for Proxy Buffer server";

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

  args = [
    "-port=${toString cfg.port}"
    "-db_path=${cfg.dbPath}"
  ]
  ++ optional cfg.enableSyncer "-enable_syncer"
  ++ optional (cfg.registryConfigFile != null) "-registry_config_file=${toString cfg.registryConfigFile}"
  ++ optional (cfg.syncerFrequency != null) "-syncer_frequency=${cfg.syncerFrequency}"
  ++ optional (cfg.syncerRecordsPerRun != null) "-syncer_records_per_run=${toString cfg.syncerRecordsPerRun}"
  ++ optional (cfg.syncerMaxRetriesPerRecord != null) "-syncer_max_retries_per_record=${toString cfg.syncerMaxRetriesPerRecord}"
  ++ optional cfg.tls.enable "-enable_tls"
  ++ optional cfg.tls.enableMlkemTls "-enable_mlkem_tls"
  ++ optional cfg.tls.enableMldsaTls "-enable_mldsa_tls"
  ++ optional (cfg.tls.certFile != null) "-service_cert=${toString cfg.tls.certFile}"
  ++ optional (cfg.tls.keyFile != null) "-service_key=${toString cfg.tls.keyFile}"
  ++ optional (cfg.tls.caCertFile != null) "-ca_root_certs=${toString cfg.tls.caCertFile}"
  ++ cfg.extraArgs;

in {
  options.services.opentitan-provisioning.pb = {
    enable = mkEnableOption "OpenTitan Proxy Buffer (PB) service";

    package = mkOption {
      type = types.package;
      defaultText = lib.literalExpression "pkgs.opentitan-provisioning.pb_server";
      description = "The pb_server package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 5001;
      description = "Port for the Proxy Buffer server to listen on.";
    };

    dbPath = mkOption {
      type = types.str;
      default = "/var/lib/opentitan/pb.db";
      description = "Path to SQLite database file (e.g. /var/lib/opentitan/pb.db or file::memory:?cache=shared).";
    };

    enableSyncer = mkOption {
      type = types.bool;
      default = false;
      description = "Enable HTTP register and syncer.";
    };

    registryConfigFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing JSON configuration for the registry.";
    };

    syncerFrequency = mkOption {
      type = types.nullOr types.str;
      default = "10m";
      description = "Frequency with which the syncer runs (valid Go duration string).";
    };

    syncerRecordsPerRun = mkOption {
      type = types.nullOr types.int;
      default = 100;
      description = "Number of records for the syncer to process per run.";
    };

    syncerMaxRetriesPerRecord = mkOption {
      type = types.nullOr types.int;
      default = 5;
      description = "Number of times a record can be retried before it stops pb_server.";
    };

    tls = mkOption {
      type = types.submodule tlsOpts;
      default = {};
      description = "TLS / mTLS configuration.";
    };

    user = mkOption {
      type = types.str;
      default = "opentitan";
      description = "User account under which the PB service runs.";
    };

    group = mkOption {
      type = types.str;
      default = "opentitan";
      description = "Group under which the PB service runs.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Additional command-line arguments to pass to pb_server.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.opentitan-pb = {
      description = "OpenTitan Proxy Buffer (PB) Service";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/pb_server ${lib.escapeShellArgs args}";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "opentitan";
        Restart = "always";
        RestartSec = "5s";
      };
    };
  };
}
