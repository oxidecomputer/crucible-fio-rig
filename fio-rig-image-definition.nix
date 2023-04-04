{ config, pkgs, lib, ... }:
let
  printerfacts = pkgs.callPackage ({ stdenv, lib, autoPatchelfHook }:
    stdenv.mkDerivation rec {
      pname = "printerfacts";
      version = "HACK";
      src = ./printerfacts;
      unpackPhase = "true"; # disable unpacking by making it run `true`
      nativeBuildInputs = [ autoPatchelfHook ];
      buildInputs = [ ];
      installPhase = ''
        install -m755 -D $src $out/bin/printerfacts
      '';
    }) {};
in {
  environment.systemPackages = [ pkgs.fio ];
  systemd.services.dropkick = {
    description = "Run the dropkick service";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig.ExecStart = "${printerfacts}/bin/printerfacts";
  };
  networking.firewall.allowedTCPPorts = [ 5000 ];
  services.openssh.enable = true;
  users.users.root.password = "hunter2";
  services.openssh.permitRootLogin = "yes";
  boot.initrd.availableKernelModules =
      [ "virtio_pci" "virtio_blk" "nvme" ];
  boot.kernelParams = [
    "console=ttyS0,1500000"
  ];
}
