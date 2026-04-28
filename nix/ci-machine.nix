{ config, pkgs, ... }:

{
  # CI User setup
  users.users.ci = {
    isNormalUser = true;
    extraGroups = [ "wheel" "podman" ];
    shell = pkgs.bash;
  };

  # System packages (global tools)
  environment.systemPackages = with pkgs; [
    vim
    git
    git-lfs
    curl
    pciutils
    usbutils
  ];

  # Podman configuration
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
  };

  # Environment initialization
  systemd.tmpfiles.rules = [
    "d /var/lib/opentitan 0755 ci users -"
  ];

  # GitHub Actions Runner Service
  services.github-runners.ot-provisioning-runner = {
    enable = true;
    url = "https://github.com/lowRISC/opentitan-provisioning";
    tokenFile = "/var/lib/secrets/github-runner-token";
    name = "ot-provisioning-nix-runner"; # UNIQUE NAME
    labels = [ "ot-provisioning-nix-runner" ]; # UNIQUE LABEL
    user = "ci";
    # Essential packages for the runner to function (checkout, etc.)
    extraPackages = with pkgs; [
      git
      git-lfs
      nix
      coreutils
      bash
    ];
  };

  # Allow the CI user to run sudo without a password
  security.sudo.extraRules = [
    {
      users = [ "ci" ];
      commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ];
    }
  ];

  # Basic system settings
  networking.hostName = "ci-machine-nix";
  time.timeZone = "UTC";
  i18n.defaultLocale = "en_US.UTF-8";

  # Enable SSH
  services.openssh.enable = true;

  # Nix settings
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Minimal boot and file system configuration for evaluation/verification
  boot.loader.grub.enable = false;
  fileSystems."/" = { device = "/dev/sda1"; fsType = "ext4"; };
}
