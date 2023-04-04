
## Running the tests locally

Right now you NEED to use propolis commit
28be85642e85afd1f47be861f920458beb3514f0, because the change to add crucible
support to propolis-standalone hasn't been merged into main yet. Artemis is
[working on it](https://github.com/oxidecomputer/propolis/pull/344), she needs
to go do a rebase and ask for a re-review.

To use this, `cargo build --release`, then run
`target/release/run_crucible_fio_test` as root.

Requirements when running:

- `cargo` on PATH.
- bhyve installed (check for `/dev/vmm`)
- permission to create bhyve VMs.
- 50 gigs of space in `/var`
  - currently the size of the disk is fixed at 16 gigs, and then you take up
    3x that because 3 regions. This will be configurable with command line flags
    later.

Be aware that if you just `pfexec ./target/release/run_crucible_fio_test` as a
normal user, it _will_ work, but it'll also change file ownerships in your
user's `.cargo` directory, because the environment is preserved. On the other
hand, the command needs cargo available when it runs, so you need cargo installed
for root if you clear your PATH. Probably what you want is something like

```
pfexec env PATH=/root/.cargo/bin:"$PATH" ./target/release/run_crucible_fio_test \
  --propolis-commit 28be85642e85afd1f47be861f920458beb3514f0 \
  --crucible-commit HEAD \
  /path/to/io_tests.fio
```

This will also handle downloading the ISO for the test image, so don't worry
about that. That ISO gets cached for repeated runs, which is useful on a local
dev machine but less so in CI where system state gets wiped. 

There is not yet a way to specify the region parameters (block size, extents) with args.

Also, the region is not filled with data before running the IO tests. We could
do that; we could even make it an argument as to whether to do it. But know that
it's not happening right now.

## Running the tests against a remote downstairs

Currently there's no way to do this. Adding support shouldn't be trouble. We need
- a way to define the downstairs addrs on the command line
- don't build crucible-downstairs/dsc when addr specified
- don't run dsc when addr specified

It'll be up to the user to make sure they pass in the same commit to the test
runner that they have running on their downstairs instance, but that should be
all there is to it. The generation number is just using the current system
time in seconds, so repeated runs against the same region will work.


## Building the OS Image

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

## to use the ISO manually outside of the rust script

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

