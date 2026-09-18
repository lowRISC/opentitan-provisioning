{ pkgs }:

let
  templatesDir = ../config/certs/templates;

  mkCerts = { name, enableMldsa ? false }:
    pkgs.runCommand name {
      nativeBuildInputs = with pkgs; [
        openssl
        gettext
      ];
      OTPROV_IP_ATE = "127.0.0.1";
      OTPROV_DNS_ATE = "localhost";
      OTPROV_IP_PA = "127.0.0.1";
      OTPROV_DNS_PA = "localhost";
      OTPROV_IP_PB = "127.0.0.1";
      OTPROV_DNS_PB = "localhost";
      OTPROV_IP_SPM = "127.0.0.1";
      OTPROV_DNS_SPM = "localhost";
    } ''
      mkdir -p $out

      ${if enableMldsa then ''
        openssl genpkey -algorithm mldsa87 \
          -provparam ml-dsa.output_formats=seed-only \
          -out $out/ca-key.pem
        openssl req -x509 -key $out/ca-key.pem -days 3650 \
          -out $out/ca-cert.pem \
          -config ${templatesDir}/ca.cnf
      '' else ''
        openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
          -keyout $out/ca-key.pem \
          -out $out/ca-cert.pem \
          -config ${templatesDir}/ca.cnf
      ''}

      for ep in ate-client pa-service pb-service spm-service; do
        envsubst < ${templatesDir}/endpoint_''${ep}.cnf.tmpl > endpoint_''${ep}.cnf

        ${if enableMldsa then ''
          openssl genpkey -algorithm mldsa87 \
            -provparam ml-dsa.output_formats=seed-only \
            -out $out/''${ep}-key.pem
          openssl req -new \
            -key $out/''${ep}-key.pem \
            -out ''${ep}-req.pem \
            -config endpoint_''${ep}.cnf
        '' else ''
          openssl req -newkey rsa:4096 -nodes \
            -keyout $out/''${ep}-key.pem \
            -out ''${ep}-req.pem \
            -config endpoint_''${ep}.cnf
        ''}

        openssl x509 -req \
          -in ''${ep}-req.pem \
          -days 3650 \
          -CA $out/ca-cert.pem \
          -CAkey $out/ca-key.pem \
          -CAcreateserial \
          -out $out/''${ep}-cert.pem \
          -extensions req_ext \
          -extfile endpoint_''${ep}.cnf
      done
    '';

  hpkeKeys = pkgs.runCommand "opentitan-test-hpke-keys" {
    nativeBuildInputs = [ pkgs.openssl ];
  } ''
    mkdir -p $out
    openssl ecparam -name prime256v1 -genkey -noout -out ecdsa.key
    openssl ec -in ecdsa.key -pubout -outform DER -out $out/hpke_ecdsa.pub.der

    openssl genpkey -algorithm mlkem768 -out mlkem.key
    openssl pkey -in mlkem.key -pubout -outform DER -out mlkem.pub.der
    openssl asn1parse -in mlkem.pub.der -inform DER -strparse 17 -noout -out $out/hpke_mlkem.pub
  '';
in
{
  rsaCerts = mkCerts { name = "opentitan-certs-rsa"; enableMldsa = false; };
  pqCerts = mkCerts { name = "opentitan-certs-pq"; enableMldsa = true; };
  inherit hpkeKeys;
}
