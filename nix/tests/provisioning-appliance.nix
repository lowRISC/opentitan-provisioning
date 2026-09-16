{ pkgs, self, testBinaries }:

let
  testPkgs = pkgs.extend self.overlays.default;
  test = testPkgs.testers.runNixOSTest {
    name = "provisioning-appliance-integration-test";

    node.specialArgs = {
      pkgs = testPkgs;
    };

    nodes.machine = { config, lib, pkgs, ... }: {
      imports = [
        self.nixosModules.provisioning-appliance-profile
      ];

      nixpkgs.overlays = lib.mkForce [ ];

      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      environment.systemPackages = [
        testBinaries
        pkgs.softhsm
        pkgs.openssl
        pkgs.sqlite
      ];

      # Configure SoftHSM for SPM
      environment.etc."softhsm2.conf".text = ''
        directories.tokendir = /var/lib/opentitan/tokens
        objectstore.backend = file
        objectstore.umask = 0077
        log.level = DEBUG
        slots.removable = false
        slots.mechanisms = ALL
        library.reset_on_fork = false
      '';

      environment.variables.SOFTHSM2_CONF = "/etc/softhsm2.conf";
      systemd.services.opentitan-spm.environment.SOFTHSM2_CONF = "/etc/softhsm2.conf";
    };

    testScript = ''
      start_all()

      # Step 1: Initialize SoftHSM token and SPM directory structure
      machine.succeed("mkdir -p /var/lib/opentitan/tokens /var/lib/opentitan/config")
      machine.succeed("chown -R opentitan:opentitan /var/lib/opentitan")
      machine.succeed("echo -n 'cryptoki' > /var/lib/opentitan/hsm_pin")
      machine.succeed("chown opentitan:opentitan /var/lib/opentitan/hsm_pin")
      machine.succeed("chmod 0600 /var/lib/opentitan/hsm_pin")

      machine.succeed(
          "sudo -u opentitan SOFTHSM2_CONF=/etc/softhsm2.conf softhsm2-util --init-token --slot=0 --so-pin=cryptoki --label=spm-hsm --pin=cryptoki"
      )

      # Step 2: Install sku_auth.yml and sku_sival.yml in SPM config dir
      machine.succeed("""
      cat << 'EOF' > /var/lib/opentitan/config/sku_auth.yml
      skuAuthCfgList:
        "sival":
          skuAuth: "$2a$10$7ZjR5zTQpig.aomnunzte.Ve1eW4GT2ACx1iy4fxtfzysprfrNMfG"
          methods: ["DeriveTokens", "GetCaSubjectKeys", "EndorseCerts", "GetCaCerts", "GetOwnerFwBootMessage", "RegisterDevice"]
      EOF

      cat << 'EOF' > /var/lib/opentitan/config/sku_sival.yml
      sku: "sival"
      slotId: 0
      numSessions: 3
      certCountX509: 3
      certCountCWT: 0
      symmetricKeys: []
      certs: []
      privateKeys: []
      publicKeys: []
      attributes:
          SeedSecHi: eg-kdf-hisec-v0
          SeedSecLo: eg-kdf-losec-v0
          WASKeyLabel: eg-kdf-hisec-v0
          WASDisable: false
          WrappingMechanism: RsaPkcs
          WrappingKeyLabel: sku-eg-rsa-rma-v0.pub
          OwnerFirmwareBootMessage: "ownership: OWND"
      x509CertHashOrder:
          - UDS
          - CDI_0
          - CDI_1
      EOF
      chown -R opentitan:opentitan /var/lib/opentitan/config
      """)

      # Step 3: Restart services and wait for them to reach active state
      machine.succeed("systemctl restart opentitan-pb.service")
      machine.wait_for_unit("opentitan-pb.service")
      machine.wait_for_open_port(5001)

      machine.succeed("systemctl restart opentitan-spm.service")
      machine.wait_for_unit("opentitan-spm.service")
      machine.wait_for_open_port(5000)

      machine.succeed("systemctl restart opentitan-pa.service")
      machine.wait_for_unit("opentitan-pa.service")
      machine.wait_for_open_port(5003)

      # Step 4: Verify services are active
      machine.succeed("systemctl is-active opentitan-pb.service")
      machine.succeed("systemctl is-active opentitan-spm.service")
      machine.succeed("systemctl is-active opentitan-pa.service")

      # Step 5: Test session connection with tls_test
      print(machine.succeed(
          "tls_test --pa_target=127.0.0.1:5003 --sku=sival --sku_auth_pw=test_password"
      ))
    '';
  };
in
test.overrideTestDerivation (old: {
  # Allow test execution in environments without hardware KVM virtualization
  requiredSystemFeatures = builtins.filter (f: f != "kvm") old.requiredSystemFeatures;
})
