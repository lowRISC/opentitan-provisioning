# SSH public keys for Provisioning Appliance administration
# Please keep alphabetized within a group.
let
  clundin = [
    # clundin
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8bsALwjQW9PZde+p6Fjwdz4UUB72O+OS339/wC56yD"
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpNIWX9+v9baRpgPC4DQIzIXpMntGCJyyL4btjdfE12RmaqrnRxJeidyR1CLcnLoclG2xJW2HgXDLYw8fE6oCwyZ89ZR0/EqgpNH+6h4FjWI/vTGT1HYdzvBV8QGkiS7ZlTk5r3H1nlMlMyhj2bvdqzztgJ2U87bJYIA1mpQ0/c/nnpr/RgW6zsWaGqk6NCkxiEEdspzJvMxqmBHrHTXxUzUltScCHhJZlBByDWndqLAzlYtJ5bqOxuzalTacekR/3TKZ6ZEPbvQA1jbo6C4M3bN+mlQ7KuJi8jErA4f6V34UmftXaP2yHP2HcmVue79yD2cbyO1Cd0SUZz/g0jnL8oxIFFg0er4h0Zoff3RckI7XfxSWqfOb2rAWdYYAl2Z/c8v3Qm20DwtW3dZ0yJu12ypn3MEJ2NanfahsT85OLBRlljpPSRlZYBVCF0EawJY2IOnOMGB7Hq/JqvNXnsUVgELpZiS5CcjY5zBwDCbK7vQVilPjBf2jWalRqXJvDfRE= clundin@clundin-glinux.c.googlers.com"
  ];
in
rec {
  inherit clundin;
  admin_keys = googler_keys;

  googler_keys = [
    # clundin
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8bsALwjQW9PZde+p6Fjwdz4UUB72O+OS339/wC56yD"
    # cfrantz
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGaE+OpSSfjOO/J6ap0dpNWHwqG0IsuMK4Ca0LY2n3L cfrantz@cfrantz-desktop.svl.corp.google.com"
    # willyzhang
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMp2SaHRjmQR9+8zlf4URB48gUS/fngEq0ZiNosAd2mm willyzha@gmail.com"
  ];
}
