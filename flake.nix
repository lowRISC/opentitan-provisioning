{
  description = "NixOS configuration and development environment for OpenTitan Provisioning";
inputs = {
  # Pinning to a stable version for consistency
  nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
};

outputs = { self, nixpkgs, ... }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };

    sharedTools = with pkgs; [
      # Base tools
      coreutils git git-lfs curl gnutar gzip unzip
      # Build tools
      bazelisk go python3 python3Packages.pip cmake gnumake gcc pkg-config
      # Libraries
      libusb1 libftdi1 openssl libp11 ncurses5 udev stdenv.cc.cc.lib
    ];

  in
  {
    # --- NIXOS CONFIGURATIONS (The Hosts) ---
    nixosConfigurations.ci-machine = nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [ ./nix/ci-machine.nix ];
    };

    # --- DEV/CI SHELL (The Builder) ---
    devShells.${system}.default = pkgs.mkShell {
      buildInputs = sharedTools;
      shellHook = ''
        echo "OpenTitan Provisioning Development Environment"
        export OT_PROV_SHELL=1
        export OPENSSL_ENGINES="${pkgs.libp11}/lib/engines"
        export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath sharedTools}:$LD_LIBRARY_PATH"
        export NIX_LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath sharedTools}"
        export NIX_LD="${pkgs.stdenv.cc.libc}/lib/ld-linux-x86-64.so.2"
      '';
    };
  };
}
