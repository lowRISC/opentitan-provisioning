{
  description = "OpenTitan Provisioning Services";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    bcr = {
      url = "github:bazelbuild/bazel-central-registry";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, bcr }:
    let
      overlay = final: prev: {
        softhsm = final.callPackage ./nix/packages/softhsm2.nix {};
        opentitan-provisioning = {
          pa_server = self.packages.${prev.stdenv.hostPlatform.system}.pa_server;
          spm_server = self.packages.${prev.stdenv.hostPlatform.system}.spm_server;
          pb_server = self.packages.${prev.stdenv.hostPlatform.system}.pb_server;
          luna-hsm-client = self.packages.${prev.stdenv.hostPlatform.system}.luna-hsm-client;
          all = self.packages.${prev.stdenv.hostPlatform.system}.all;
        };
      };

      nixosModule = { config, lib, pkgs, ... }: {
        imports = [ ./nix/modules ];
        nixpkgs.overlays = lib.mkDefault [ overlay ];
        services.opentitan-provisioning.pa.package = lib.mkDefault pkgs.opentitan-provisioning.pa_server;
        services.opentitan-provisioning.spm.package = lib.mkDefault pkgs.opentitan-provisioning.spm_server;
        services.opentitan-provisioning.pb.package = lib.mkDefault pkgs.opentitan-provisioning.pb_server;
      };

      perSystem = flake-utils.lib.eachDefaultSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = pkg:
              builtins.elem (nixpkgs.lib.getName pkg) [ "luna-hsm-client" "610" ];
          };

          bazelPackages = import ./nix/bazel.nix {
            inherit pkgs bcr;
            src = ./.;
          };
          inherit (bazelPackages) pa_server spm_server pb_server services testBinaries bazelDepsCache;
          luna-hsm-client = pkgs.callPackage ./nix/packages/luna-hsm-client.nix {};

          applianceSystem = nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              nixosModule
              ./nix/profiles/provisioning-appliance.nix
              ({ lib, ... }: {
                networking.hostName = "provisioning-appliance";
                system.stateVersion = "24.11";
                fileSystems."/" = lib.mkDefault { device = "/dev/null"; fsType = "ext4"; };
              })
            ];
          };

          cryptoAssets = import ./nix/crypto-assets.nix { inherit pkgs; };
          softhsm2 = pkgs.callPackage ./nix/packages/softhsm2.nix {};

          ciDepsCache = pkgs.writeText "opentitan-ci-deps-cache" ''
            ${bazelDepsCache}
            ${softhsm2}
            ${cryptoAssets.rsaCerts}
            ${cryptoAssets.pqCerts}
            ${cryptoAssets.hpkeKeys}
          '';

          checks = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            provisioning-appliance = import ./nix/tests/provisioning-appliance.nix {
              inherit pkgs self testBinaries cryptoAssets;
            };
          };
        in {
          inherit checks;

          packages = {
            all = services;
            default = services;
            inherit pa_server spm_server pb_server luna-hsm-client;
            bazel-deps-cache = ciDepsCache;
            test-binaries = testBinaries;
            provisioning-appliance-vm = applianceSystem.config.system.build.vm;
          };

          apps = {
            pa_server = flake-utils.lib.mkApp {
              drv = pa_server;
              name = "pa_server";
            };
            spm_server = flake-utils.lib.mkApp {
              drv = spm_server;
              name = "spm_server";
            };
            pb_server = flake-utils.lib.mkApp {
              drv = pb_server;
              name = "pb_server";
            };
            provisioning-appliance-vm = flake-utils.lib.mkApp {
              drv = applianceSystem.config.system.build.vm;
              name = "run-provisioning-appliance-vm";
            };
            default = self.apps.${system}.pa_server;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              softhsm2
            ] ++ (with pkgs; [
              bazel_8
              bazelisk
              go
              gopls
              protobuf
              pkg-config
              systemd
              libusb1
              openssl
              git-lfs
              gettext
            ]);
            USE_BAZEL_VERSION = "${pkgs.bazel_8.version}";
          };
        }
      );
    in
      perSystem // {
        keys = import ./nix/keys.nix;
        overlays.default = overlay;
        nixosModules = {
          opentitan-provisioning = nixosModule;
          default = nixosModule;
          provisioning-appliance-profile = {
            imports = [
              nixosModule
              ./nix/profiles/provisioning-appliance.nix
            ];
          };
          ci-profile = ./nix/profiles/ci.nix;
          softhsm-profile = ./nix/profiles/softhsm.nix;
          luna-hsm-profile = ./nix/profiles/luna-hsm.nix;
        };

        nixosConfigurations.provisioning-appliance = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            self.nixosModules.provisioning-appliance-profile
            self.nixosModules.luna-hsm-profile
            self.nixosModules.ci-profile
            ./nix/hardware-configuration.nix
            ({ lib, ... }: {
              networking.hostName = "provisioning-appliance";
              system.stateVersion = "24.11";
              boot.loader.systemd-boot.enable = lib.mkDefault true;
              boot.loader.efi.canTouchEfiVariables = lib.mkDefault true;
              fileSystems."/" = lib.mkDefault {
                device = "/dev/disk/by-label/nixos";
                fsType = "ext4";
              };
            })
          ];
        };
      };
}
