{ config, lib, pkgs, ... }:

{
  # Device permissions for OpenTitan FPGA and debug boards (CW340, FTDI, HyperDebug)
  services.udev.extraRules = ''
    # NewAE Technology Inc. ChipWhisperer boards (CW340, CW305, CW-Lite, CW-Husky)
    ACTION=="add|change", SUBSYSTEM=="usb|tty", ATTRS{idVendor}=="2b3e", ATTRS{idProduct}=="ace[0-9]|c[3-6][0-9][0-9]", MODE="0666"

    # Future Technology Devices International, Ltd FT2232C/D/H Dual/Quad UART/FIFO IC
    ACTION=="add|change", SUBSYSTEM=="usb|tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="601[01]", MODE="0666"
    ACTION=="add|change", SUBSYSTEM=="usb|tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", MODE="0666"

    # Google HyperDebug
    ACTION=="add|change", SUBSYSTEM=="usb|tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", MODE="0666", SYMLINK+="hyperdebug_dfu"
    ACTION=="add|change", SUBSYSTEM=="usb|tty", ATTRS{idVendor}=="18d1", ATTRS{idProduct}=="520e", MODE="0666", SYMLINK+="hyperdebug"
  '';

  # Add dialout group for serial console access
  users.users.opentitan.extraGroups = [ "dialout" ];
  users.users.admin.extraGroups = [ "dialout" ];

  # OpenTitan CI / FPGA debugging and testing dependencies
  environment.systemPackages = with pkgs; [
    usbutils
    openocd
    git
    git-lfs
    file
    curl
    python3
    gettext
  ];

  # Allow dynamically linked OpenTitan host binaries (e.g. opentitantool) to run on NixOS
  programs.nix-ld.enable = true;
  programs.nix-ld.libraries = with pkgs; [
    stdenv.cc.cc
    systemd
    libusb1
    libftdi1
    openssl
    zlib
  ];
}
