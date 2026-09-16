{ stdenv
, fetchurl
, cmake
, ninja
, pkg-config
, openssl
, sqlite
}:

stdenv.mkDerivation {
  pname = "softhsm2-pq";
  version = "2.6.1-unstable-2025-01-20";

  src = fetchurl {
    url = "https://github.com/opendnssec/SoftHSMv2/archive/6319797ff0d11578375965d3a5b2bba7a81e03f0.tar.gz";
    sha256 = "35b3131364a1af4578868f98916e7a0b74c13520214c147888a728d39bb2a9ee";
  };

  patches = [
    ../third_party/softhsm2/0002-Include-time.patch
    ../third_party/softhsm2/0003-Fix-MLDSA-include-path.patch
  ];

  postPatch = ''
    sed -i 's/#define SOFTHSM_LOG_FILE_AND_LINE//' src/lib/common/log.h
  '';

  nativeBuildInputs = [
    cmake
    ninja
    pkg-config
  ];

  buildInputs = [
    openssl
    sqlite
  ];

  NIX_CFLAGS_COMPILE = "-DWITH_ML_DSA -DWITHOUT_OPENSSL_ENGINES";

  cmakeFlags = [
    "-DENABLE_GOST=OFF"
    "-DENABLE_P11_KIT=OFF"
    "-DENABLE_STATIC=OFF"
    "-DENABLE_ECC=ON"
    "-DENABLE_EDDSA=ON"
    "-DENABLE_MLDSA=ON"
    "-DWITH_CRYPTO_BACKEND=openssl"
    "-DCMAKE_INSTALL_LOCALSTATEDIR=var/lib/softhsm"
    "-DCMAKE_INSTALL_SYSCONFDIR=etc"
    "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-Bsymbolic"
  ];
}
