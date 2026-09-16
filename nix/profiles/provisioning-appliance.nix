{ config, lib, pkgs, ... }:

let
  keys = import ../keys.nix;
in
{
  services.opentitan-provisioning = {
    pa = {
      enable = true;
      port = lib.mkDefault 5003;
      spmAddress = lib.mkDefault "127.0.0.1:5000";
      enableRegistry = lib.mkDefault true;
      registryAddress = lib.mkDefault "127.0.0.1:5001";
    };

    spm = {
      enable = true;
      port = lib.mkDefault 5000;
      configDir = lib.mkDefault "/var/lib/opentitan/config";
      authConfig = lib.mkDefault "sku_auth.yml";
    };

    pb = {
      enable = true;
      port = lib.mkDefault 5001;
      dbPath = lib.mkDefault "/var/lib/opentitan/pb.db";
      enableSyncer = lib.mkDefault false;
    };
  };

  # Ensure base state directories exist
  systemd.tmpfiles.rules = [
    "d /var/lib/opentitan 0750 opentitan opentitan -"
    "d /var/lib/opentitan/config 0750 opentitan opentitan -"
  ];

  networking.firewall.allowedTCPPorts = [ config.services.opentitan-provisioning.pa.port ];

  environment.systemPackages = with pkgs; [
    sqlite
    tmux
    picocom
  ];

  # User credentials for the Provisioning Appliance:
  users.mutableUsers = lib.mkDefault false;
  users.users.opentitan = {
    isNormalUser = true;
    isSystemUser = lib.mkForce false;
    extraGroups = [ "wheel" "opentitan" ];
    password = "opentitan";
    home = "/home/opentitan";
    createHome = true;
  };
  users.users.root.password = lib.mkDefault "opentitan";

  # Enable passwordless sudo for convenience in appliance/VM environment
  security.sudo.wheelNeedsPassword = false;

  # Auto-login on virtual console
  services.getty.autologinUser = lib.mkDefault "opentitan";

  # Admin user for remote management and nixos-rebuild
  users.users.admin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = keys.admin_keys;
    password = lib.mkDefault "admin";
  };

  # SSH service for remote updates
  services.openssh = {
    enable = lib.mkDefault true;
    settings = {
      PasswordAuthentication = lib.mkDefault true;
      PermitRootLogin = lib.mkDefault "prohibit-password";
    };
  };

  # Allow trusted users to deploy closures / run nixos-rebuild over SSH and enable flakes
  nix.settings = {
    trusted-users = [ "root" "@wheel" ];
    experimental-features = [ "nix-command" "flakes" ];
  };
}
