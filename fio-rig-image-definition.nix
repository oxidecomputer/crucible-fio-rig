# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

{ config, pkgs, lib, ... }:
let
  # Don't you dare do a getty, not even once buddy.  Realistically this is
  # redundant because NixOS doesn't getty on ttyS0 unless the linux console is
  # set to that, but just in case that changes, this is insurance.
  systemd.services."serial-getty@".enable = lib.mkForce false;
  # systemd.services."getty@".enable = lib.mkForce false;
  crucibleFioRig = pkgs.callPackage ({ stdenv, lib, autoPatchelfHook }:
    stdenv.mkDerivation rec {
      pname = "crucibleFioRig";
      version = "irrelevant";
      src = ./target/release/fio_rig_server;
      unpackPhase = "true"; # disable unpacking by making it run `true`
      nativeBuildInputs = [ autoPatchelfHook ];
      buildInputs = [
        pkgs.systemd # needed for libudev.so
      ];
      installPhase = ''
        install -m755 -D $src $out/bin/fio_rig_server
      '';
    }) { };
in {
  systemd.services.fioRig = {
    description = "Run the fio rig server component";
    wantedBy = [ "multi-user.target" ];
    serviceConfig.ExecStart = "${crucibleFioRig}/bin/fio_rig_server";
    path = [ pkgs.fio ];
  };
  # TODO take these out when we're done debugging.
  services.openssh.enable = true;
  users.users.root.password = "hunter2";
  services.openssh.permitRootLogin = "yes";
  boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "nvme" ];
  boot.kernelParams = [
    # "console=ttyS0,1500000"
    # Use a virtual console, because we're using the real serial for our own
    # comms
    "console=ttyS1"
  ];
  isoImage.squashfsCompression = "zstd -Xcompression-level 3";
}
