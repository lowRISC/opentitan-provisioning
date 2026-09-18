{ pkgs, self, testBinaries, cryptoAssets }:

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
        self.nixosModules.softhsm-profile
      ];

      nixpkgs.overlays = lib.mkForce [ ];

      virtualisation.memorySize = 4096;
      virtualisation.cores = 4;

      environment.systemPackages = [
        testBinaries
        testPkgs.softhsm
        pkgs.openssl
        pkgs.sqlite
      ];

      # Provide testBinaries (hsmtool, tbsgen) to opentitan-hsm-init service
      systemd.services.opentitan-hsm-init.path = [ testBinaries ];

      # Stage config.tar.gz and HPKE public keys so opentitan-hsm-init automatically
      # initializes all 5 SKUs (sival, cr01, pi01, ti01, sival_pqc) and HPKE keys on boot
      systemd.tmpfiles.rules = [
        "d /var/lib/opentitan/release 0750 opentitan opentitan -"
        "d /var/lib/opentitan/release/hpke 0750 opentitan opentitan -"
        "C /var/lib/opentitan/release/config.tar.gz 0640 opentitan opentitan - ${testBinaries}/share/opentitan/config.tar.gz"
        "C /var/lib/opentitan/release/hpke/hpke_mlkem.pub 0640 opentitan opentitan - ${cryptoAssets.hpkeKeys}/hpke_mlkem.pub"
        "C /var/lib/opentitan/release/hpke/hpke_ecdsa.pub.der 0640 opentitan opentitan - ${cryptoAssets.hpkeKeys}/hpke_ecdsa.pub.der"
      ];

      # Default configuration: PQ mTLS (ML-DSA-87 + ML-KEM)
      services.opentitan-provisioning = {
        pa.tls = {
          enable = true;
          enableMlkemTls = true;
          enableMldsaTls = true;
          certFile = "${cryptoAssets.pqCerts}/pa-service-cert.pem";
          keyFile = "${cryptoAssets.pqCerts}/pa-service-key.pem";
          caCertFile = "${cryptoAssets.pqCerts}/ca-cert.pem";
        };
        spm.tls = {
          enable = true;
          enableMlkemTls = true;
          enableMldsaTls = true;
          certFile = "${cryptoAssets.pqCerts}/spm-service-cert.pem";
          keyFile = "${cryptoAssets.pqCerts}/spm-service-key.pem";
          caCertFile = "${cryptoAssets.pqCerts}/ca-cert.pem";
        };
        pb.tls = {
          enable = true;
          enableMlkemTls = true;
          enableMldsaTls = true;
          certFile = "${cryptoAssets.pqCerts}/pb-service-cert.pem";
          keyFile = "${cryptoAssets.pqCerts}/pb-service-key.pem";
          caCertFile = "${cryptoAssets.pqCerts}/ca-cert.pem";
        };
      };

      # Specialisation: Classical RSA-4096 mTLS
      specialisation.rsa.configuration = {
        services.opentitan-provisioning = {
          pa.tls = {
            enable = lib.mkForce true;
            enableMlkemTls = lib.mkForce false;
            enableMldsaTls = lib.mkForce false;
            certFile = lib.mkForce "${cryptoAssets.rsaCerts}/pa-service-cert.pem";
            keyFile = lib.mkForce "${cryptoAssets.rsaCerts}/pa-service-key.pem";
            caCertFile = lib.mkForce "${cryptoAssets.rsaCerts}/ca-cert.pem";
          };
          spm.tls = {
            enable = lib.mkForce true;
            enableMlkemTls = lib.mkForce false;
            enableMldsaTls = lib.mkForce false;
            certFile = lib.mkForce "${cryptoAssets.rsaCerts}/spm-service-cert.pem";
            keyFile = lib.mkForce "${cryptoAssets.rsaCerts}/spm-service-key.pem";
            caCertFile = lib.mkForce "${cryptoAssets.rsaCerts}/ca-cert.pem";
          };
          pb.tls = {
            enable = lib.mkForce true;
            enableMlkemTls = lib.mkForce false;
            enableMldsaTls = lib.mkForce false;
            certFile = lib.mkForce "${cryptoAssets.rsaCerts}/pb-service-cert.pem";
            keyFile = lib.mkForce "${cryptoAssets.rsaCerts}/pb-service-key.pem";
            caCertFile = lib.mkForce "${cryptoAssets.rsaCerts}/ca-cert.pem";
          };
        };
      };
    };

    testScript = ''
      start_all()

      # Wait for HSM initialization and all provisioning services (PQ mode)
      machine.wait_for_unit("opentitan-hsm-init.service")
      machine.wait_for_unit("opentitan-pb.service")
      machine.wait_for_open_port(5001)
      machine.wait_for_unit("opentitan-spm.service")
      machine.wait_for_open_port(5000)
      machine.wait_for_unit("opentitan-pa.service")
      machine.wait_for_open_port(5003)

      # 1. TLS Test (PQ: ML-DSA-87 + ML-KEM)
      print("=== Running TLS Test (PQ) ===")
      print(machine.succeed(
          "tls_test"
          " --pa_target=localhost:5003"
          " --sku=sival"
          " --sku_auth_pw=test_password"
          " --enable_mtls=true"
          " --enable_mlkem_tls=true"
          " --enable_mldsa_tls=true"
          " --ca_root_certs=${cryptoAssets.pqCerts}/ca-cert.pem"
          " --client_cert=${cryptoAssets.pqCerts}/ate-client-cert.pem"
          " --client_key=${cryptoAssets.pqCerts}/ate-client-key.pem"
      ))

      # 2. PA Loadtest (PQ: ML-DSA-87 + ML-KEM + ML-DSA DICE + all 5 SKUs including sival_pqc)
      print("=== Running PA Loadtest (PQ) ===")
      print(machine.succeed(
          "sudo -u opentitan env SOFTHSM2_CONF=/etc/softhsm2.conf SPM_HSM_PIN_USER=cryptoki HSMTOOL_PIN=cryptoki"
          " pa_loadtest"
          " --pa_address=localhost:5003"
          " --enable_tls=true"
          " --enable_mlkem_tls=true"
          " --enable_mldsa_tls=true"
          " --enable_mldsa_dice=true"
          " --ca_root_certs=${cryptoAssets.pqCerts}/ca-cert.pem"
          " --client_cert=${cryptoAssets.pqCerts}/ate-client-cert.pem"
          " --client_key=${cryptoAssets.pqCerts}/ate-client-key.pem"
          " --spm_config_dir=/var/lib/opentitan/config"
          " --hsm_so=${testPkgs.softhsm}/lib/softhsm/libsofthsm2.so"
          " --sku_names=sival,cr01,pi01,ti01,sival_pqc"
          " --parallel_clients=5"
          " --total_duts=10"
          " --sku_auth=test_password"
      ))

      # 3. Switch to Classical RSA-4096 specialisation
      print("=== Switching to RSA Specialisation ===")
      machine.succeed("/run/current-system/specialisation/rsa/bin/switch-to-configuration test")
      machine.wait_for_unit("opentitan-pb.service")
      machine.wait_for_open_port(5001)
      machine.wait_for_unit("opentitan-spm.service")
      machine.wait_for_open_port(5000)
      machine.wait_for_unit("opentitan-pa.service")
      machine.wait_for_open_port(5003)

      # 4. TLS Test (RSA-4096)
      print("=== Running TLS Test (RSA) ===")
      print(machine.succeed(
          "tls_test"
          " --pa_target=localhost:5003"
          " --sku=sival"
          " --sku_auth_pw=test_password"
          " --enable_mtls=true"
          " --enable_mlkem_tls=false"
          " --enable_mldsa_tls=false"
          " --ca_root_certs=${cryptoAssets.rsaCerts}/ca-cert.pem"
          " --client_cert=${cryptoAssets.rsaCerts}/ate-client-cert.pem"
          " --client_key=${cryptoAssets.rsaCerts}/ate-client-key.pem"
      ))

      # 5. PA Loadtest (RSA-4096)
      print("=== Running PA Loadtest (RSA) ===")
      print(machine.succeed(
          "sudo -u opentitan env SOFTHSM2_CONF=/etc/softhsm2.conf SPM_HSM_PIN_USER=cryptoki HSMTOOL_PIN=cryptoki"
          " pa_loadtest"
          " --pa_address=localhost:5003"
          " --enable_tls=true"
          " --enable_mlkem_tls=false"
          " --enable_mldsa_tls=false"
          " --enable_mldsa_dice=false"
          " --ca_root_certs=${cryptoAssets.rsaCerts}/ca-cert.pem"
          " --client_cert=${cryptoAssets.rsaCerts}/ate-client-cert.pem"
          " --client_key=${cryptoAssets.rsaCerts}/ate-client-key.pem"
          " --spm_config_dir=/var/lib/opentitan/config"
          " --hsm_so=${testPkgs.softhsm}/lib/softhsm/libsofthsm2.so"
          " --sku_names=sival,cr01,pi01,ti01"
          " --parallel_clients=5"
          " --total_duts=10"
          " --sku_auth=test_password"
      ))
    '';
  };
in
test.overrideTestDerivation (old: {
  # Allow test execution in environments without hardware KVM virtualization
  requiredSystemFeatures = builtins.filter (f: f != "kvm") old.requiredSystemFeatures;
})
