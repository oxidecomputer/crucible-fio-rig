i will make this readme more illuminating when im dying less. I'll also improve
the project when I'm dying less. which will be soon. (- artemis)

this nix build isnt good and should be made better like the OKS one. but anyway, for now:

```
# install nixos-generators if you dont have it
nix-env -f https://github.com/nix-community/nixos-generators/archive/master.tar.gz -i

# part of whats bad is that its pulling the binary out of target/ instead of building it in nix. TODO
cargo build --release

# generate the iso
nixos-generate -f iso -c fio-rig-image-definition.nix

iso is in result/something/nixos.iso
```

to use the ISO manually outside of my WIP rust CI script

- make sure the ISO is mounted with virtio
- make sure the FS you want to test is mounted with nvme
- if you don't want to do those two things, change the `--filename` in the code
  in `src/bin/fio_rig_server.rs`, line 109-ish
- connect some client bidirectionally to the serial that sends it tests and
  gets results back.

we also need to write some kinda standalone client to talk to it if we want to
use it outside of the CI thing im building, i guess. code needs to be extracted
out of `src/bin/run_crucible_fio_test.rs`, but it's mostly encapsulated anyway.
you want the `run_fio_tests_on_rig` function, though maybe you want to abstract
it to work on anything with `Read+Write` instead of specifically a UnixStream.


btw for the main CI thing, we want this PR https://github.com/oxidecomputer/propolis/pull/344
