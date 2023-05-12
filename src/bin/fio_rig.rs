// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, bail, ensure, Context, Result};
use argh::FromArgs;
use camino::{Utf8Path, Utf8PathBuf};
use crucible_fio_rig::{
    build_crucible_and_propolis::{build_crucible_and_propolis, BuiltExecutables},
    fio_rig_protocol::{
        FioRigRequest, FioRigResponse, FioTestDefinition, FioTestErr, FioTestResult,
        ALIGNMENT_SEQUENCE,
    },
};
use futures::prelude::*;
use std::{
    collections::VecDeque,
    fs::File,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::mpsc,
    thread::{self, sleep},
    time::{Duration, Instant, SystemTime},
};
use tempfile;
use tokio_serde::formats::MessagePack;
use tokio_util::codec::LengthDelimitedCodec;
use toml_edit::{value, Array, Document};

// hashes here are blake3, generate with b3sum from `cargo install b3sum`
const BOOTROM_DOWNLOAD_URL: &str =
    "https://oxide-omicron-build.s3.amazonaws.com/OVMF_CODE_20220922.fd";
const BOOTROM_HASH: &str = "fbeb0d100f8e8bbe12c558806c1ad0d8a88abf7a818eb04ef92498d61d31e2a4";
const BOOTROM_FILENAME: &str = "OVMF_CODE.fd";

// TODO move this to oxide infrastructure
const ISO_DOWNLOAD_URL: &str =
    "https://pkg.artemis.sh/oxide/crucible_fio_rig/fio-rig-2023-04-03.iso";
const ISO_HASH: &str = "2e0dd54003248e1761d34f5038919fac32541e9371010185349ac6919b90f8f6";
const ISO_FILENAME: &str = "fio-rig.iso";

/// bootrom and iso will be stored here.
const CACHE_DIR: &str = "/var/cache/crucible-propolis-fio-test";
const VAR_DIR: &str = "/var/crucible_fio_rig";

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "build-propolis-with-crucible")]
/// Build propolis and crucible together. Prints out json containing the paths
/// to the build crucible-downstairs, dsc, and propolis-standalone binaries.
struct BuildPropolisWithCrucibleCmd {
    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/crucible.git\")"
    )]
    /// repo url of crucible to use for upstairs/downstairs, defaults to
    /// github oxidecomputer/crucible
    crucible_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of crucible to use for upstairs/downstairs
    crucible_commit: String,

    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/propolis.git\")"
    )]
    /// repo url of propolis to use for upstairs/downstairs, defaults to
    /// github oxidecomputer/propolis
    propolis_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of propolis to check out
    propolis_commit: String,

    #[argh(option, default = "String::from(\".\")")]
    /// directory within which to clone/build code. defaults to current
    /// working directory.
    work_dir: String,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "run-fio-test-in-vm")]
/// Build propolis with a given commit hash of crucible, and run some fio
/// tests in a VM on it. Output is printed to stdout or written to a
/// specified output file
struct RunCrucibleFioTestCmd {
    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/crucible.git\")"
    )]
    /// repo url of crucible to use for upstairs/downstairs, defaults to
    /// github oxidecomputer/crucible
    crucible_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of crucible to use for upstairs/downstairs
    crucible_commit: String,

    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/propolis.git\")"
    )]
    /// repo url of propolis to use for upstairs/downstairs, defaults to
    /// github oxidecomputer/propolis
    propolis_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of propolis to check out
    propolis_commit: String,

    #[argh(option, default = "String::from(\"normal\")")]
    /// fio output format, see fio help for more details. When normal or terse,
    /// output will be formatted as the fio test path, the fio test
    /// result/error, and then a few newlines. With json or json+, output will
    /// be syntactically correct json.
    output_format: String,

    #[argh(option, default = "String::from(\"-\")")]
    /// if specified, output will be written to to this file. Otherwise,
    /// output will be written to STDOUT. Specifying `-` will also send
    /// output to STDOUT.
    output_file: String,

    #[argh(positional)]
    /// fio job files on disk that should be sent to the VM to execute.
    fio_jobs: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// fio rig. see help for individual subcommands.
struct FioRigCmd {
    #[argh(subcommand)]
    subcmd: FioRigSubCmd,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum FioRigSubCmd {
    BuildPropolisWithCrucible(BuildPropolisWithCrucibleCmd),
    RunCrucibleFioTest(RunCrucibleFioTestCmd),
}

pub fn main() -> Result<()> {
    // TODO ctrl_c handling
    // MISC TODO: run all the Command()s with stuff piped to slog or something
    let cmd: FioRigCmd = argh::from_env();

    match cmd.subcmd {
        FioRigSubCmd::BuildPropolisWithCrucible(cmd) => build_propolis_with_crucible_main(cmd),
        FioRigSubCmd::RunCrucibleFioTest(cmd) => run_crucible_fio_test_main(cmd),
    }?;
    Ok(())
}

fn build_propolis_with_crucible_main(cmd: BuildPropolisWithCrucibleCmd) -> Result<()> {
    let work_dir_path = Utf8PathBuf::from(cmd.work_dir);

    let built_executables = build_crucible_and_propolis(
        &cmd.crucible_url,
        &cmd.crucible_commit,
        &cmd.propolis_url,
        &cmd.propolis_commit,
        &work_dir_path,
    )?;

    serde_json::to_writer(std::io::stdout(), &built_executables)?;

    Ok(())
}

fn run_crucible_fio_test_main(cmd: RunCrucibleFioTestCmd) -> Result<()> {
    if cmd.fio_jobs.is_empty() {
        bail!("no fio jobs specified");
    }

    // Read all the job files
    let mut fio_jobs = Vec::with_capacity(cmd.fio_jobs.len());
    for (job_id, path) in cmd.fio_jobs.into_iter().enumerate() {
        let mut job_file = File::open(&path)?;
        let mut job_bytes = Vec::new();
        job_file.read_to_end(&mut job_bytes)?;
        let job_contents = String::from_utf8(job_bytes)?;
        fio_jobs.push(FioTestDefinition {
            id: job_id as u64,
            name: path,
            fio_job: job_contents,
            fio_args: Vec::new(), // TODO do we need any args?
        });
    }

    // work dir in tmp
    std::fs::create_dir_all(VAR_DIR)?;
    let work_dir = tempfile::tempdir_in(VAR_DIR)?;
    let work_dir_path = Utf8Path::from_path(work_dir.path())
        .unwrap_or_else(|| panic!("tfw your filepath isn't valid UTF-8: {:?}", work_dir.path()));

    // YYY::vi next up we want to probably pass BuiltExecutables in from main(),
    // that way they can get specified as command line args. then we can
    // optionally split the build/run or do them both together depending on
    // usecase. Except we also want a way to pass in only the path to propolis
    // if we're running against a remote downstairs- which we don't support yet,
    // but should.
    let BuiltExecutables {
        dsc_exe,
        downstairs_exe,
        propolis_standalone_exe,
    } = build_crucible_and_propolis(
        &cmd.crucible_url,
        &cmd.crucible_commit,
        &cmd.propolis_url,
        &cmd.propolis_commit,
        work_dir_path,
    )?;

    let fio_results = run_crucible_fio_tests(
        &dsc_exe,
        &downstairs_exe,
        &propolis_standalone_exe,
        work_dir_path,
        fio_jobs,
    )?;

    let mut results_output: Box<dyn Write> = if cmd.output_file == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(File::create(cmd.output_file)?)
    };

    if cmd.output_format.contains("json") {
        // TODO parse individual result jsons and merge them is I think what
        // we wanted to do here.
    } else {
        for result in fio_results {
            match result {
                Ok(result) => {
                    write!(
                        results_output,
                        "Results for test {} - {}\n",
                        result.id, result.name
                    )?;
                    results_output.write_all(result.results.as_bytes())?;
                }
                Err(err) => {
                    write!(
                        results_output,
                        "Test failure for test {} - {}\n",
                        err.id, err.name
                    )?;
                    results_output.write_all(err.err.as_bytes())?
                }
            }
            write!(results_output, "\n\n\n")?;
        }
    }

    results_output.flush()?;

    Ok(())
}

pub fn run_crucible_fio_tests(
    dsc_exe: &Utf8Path,
    downstairs_exe: &Utf8Path,
    propolis_standalone_exe: &Utf8Path,
    work_dir_path: &Utf8Path,
    fio_jobs: Vec<FioTestDefinition>,
) -> Result<Vec<Result<FioTestResult, FioTestErr>>> {
    if !Utf8PathBuf::from_str("/dev/vmm").unwrap().try_exists()? {
        bail!("/dev/vmm doesn't exist - is bhyve installed?");
    }

    let disk = DownstairsTrinity {
        ds_addrs: [
            SocketAddr::from_str("127.0.0.1:8810").unwrap(),
            SocketAddr::from_str("127.0.0.1:8820").unwrap(),
            SocketAddr::from_str("127.0.0.1:8830").unwrap(),
        ],
        block_size: 4096,
        blocks_per_extent: 32768,
        extent_count: 8 * 8,
    };

    let dsc_proccess = launch_downstairs(&disk, &dsc_exe, &downstairs_exe, &work_dir_path)?;

    // We'll run the rest of the tests in their own Result block, so we can
    // cleanly shut down dsc even when errors happen
    let fio_results = {
        // Run a VM with propolis-standalone
        let vm_name = generate_vm_name();
        let (mut propolis_proc, vm_serial) = launch_fio_test_vm(
            &vm_name,
            2,
            2048,
            &disk,
            &propolis_standalone_exe,
            &work_dir_path,
        )?;

        // Run fio tests
        let fio_results = run_fio_tests_on_rig(fio_jobs, vm_serial)?;

        // Close down propolis process
        let _ = propolis_proc.kill();
        // Wait up to 10 seconds, then move on with our life
        for _ in 0..10 {
            if let Ok(Some(_)) = propolis_proc.try_wait() {
                break;
            }
            sleep(Duration::from_secs(1));
        }

        // Clean up the VM resources. Ignore failure because ultimately we just
        // want to bubble up the results, this is best effort.
        let _ = destroy_bhyve_vm(&vm_name);

        Ok(fio_results)
    };

    // Just print the error because there's nothing we can do about it, and we
    // already have results to return.
    let shutdown_err = shutdown_downstairs(dsc_proccess, &dsc_exe);
    if let Err(err) = shutdown_err {
        eprintln!("Error shutting down dsc: \n{}", err.to_string())
    }

    fio_results
}

/// Download a file to the path if there is no file there or the file currently
/// there doesn't match the expected hash. Errors if the downloaded file does
/// not match the expected hash
fn download_if_needed(path: &Utf8Path, url: &str, expected_hash: blake3::Hash) -> Result<()> {
    let check_hash = || -> Result<()> {
        let mut file = File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finalize();
        if hash == expected_hash {
            Ok(())
        } else {
            Err(anyhow!(
                "hash mismatch downloading {} to {}: expected {} but got {}",
                url,
                path,
                expected_hash,
                hash
            ))
        }
    };

    if path.exists() {
        match check_hash() {
            // File is what we expect!
            Ok(()) => return Ok(()),
            // If the file exists but is the wrong hash, delete and redownload.
            Err(err) => {
                eprintln!("Redownloading file at {}, because it doesn't match the expected hash. Here's the hash check message: {}", path.as_str(), err.to_string());
                std::fs::remove_file(path)?;
            }
        }
    }

    {
        eprintln!("Downloading {} to {}", url, path);
        let mut download = reqwest::blocking::get(url)?;
        let mut file = File::create(path)?;
        download.copy_to(&mut file)?;
        file.flush()?;
    }

    // Do a final hash check to make sure what we just downloaded is what we
    // expected
    check_hash()
}

/// Download bootrom if its not downloaded, either way return the path to the
/// bootrom.
fn download_bootrom_if_needed() -> Result<Utf8PathBuf> {
    // TODO refactor into download function
    let path = Utf8PathBuf::from(CACHE_DIR).join(BOOTROM_FILENAME);
    let expected_hash = blake3::Hash::from_hex(BOOTROM_HASH).unwrap();
    download_if_needed(&path, BOOTROM_DOWNLOAD_URL, expected_hash)
        .context("Downloading bootrom")?;
    Ok(path)
}

fn download_fio_test_iso_if_needed() -> Result<Utf8PathBuf> {
    let path = Utf8PathBuf::from(CACHE_DIR).join(ISO_FILENAME);
    let expected_hash = blake3::Hash::from_hex(ISO_HASH).unwrap();
    download_if_needed(&path, ISO_DOWNLOAD_URL, expected_hash).context("Downloading iso")?;
    Ok(path)
}

/// generate an unused VM name. This just looks in /dev/vmm to find existing VMs
fn generate_vm_name() -> String {
    let dev_vmm = Utf8PathBuf::from_str("/dev/vmm").unwrap();

    // This pool doesn't need to be big, it's just for fun. The number we throw
    // on the end is the main thing preventing colissions.
    const DIVINES: [&str; 14] = [
        "DETACHMENT",
        "DISCOVERY",
        "DISINTEREST",
        "EMPATHY",
        "FORTITUDE",
        "GRACE",
        "INTEGRITY",
        "LIBERTY",
        "LOYALTY",
        "ORDER",
        "PATIENCE",
        "PEACE",
        "RIGHTEOUSNESS",
        "VOICE",
    ];

    let divine: &str = DIVINES[rand::random::<usize>() % DIVINES.len()];
    let suffix: u32 = rand::random();
    let vm_name = format!("{}{}", divine, suffix);
    let vm_path = dev_vmm.join(&vm_name);
    if vm_path.exists() {
        // normal recursion is fine, chances of colliding even a single time is
        // slim, much less multiple times.
        generate_vm_name()
    } else {
        vm_name
    }
}

/// Launch a VM with a given name and ISO path. Returns the child process and a
/// serial connection. No networking is provided.
fn launch_fio_test_vm(
    vm_name: &str,
    cpu_cores: u8,
    memory: u32,
    disk: &DownstairsTrinity,
    propolis_exe: &Utf8Path,
    work_dir_path: &Utf8Path,
) -> Result<(Child, UnixStream)> {
    // Build the config file
    let base_config_toml = r#"
    [main]

    [block_dev.boot_iso]
    type = "file"

    [block_dev.test_disk]
    type = "crucible"

    [dev.block0]
    driver = "pci-virtio-block"
    block_dev = "boot_iso"
    pci-path = "0.4.0"

    [dev.block1]
    driver = "pci-nvme"
    block_dev = "test_disk"
    pci-path = "0.5.0"
    "#;
    let mut vm_config = base_config_toml.parse::<Document>().unwrap();
    let bootrom_path = download_bootrom_if_needed()?;

    // copy cached iso to work_dir, because for some reason it gets modified
    // during execution. That modification invalidates the cache! So we make
    // a copy of the cached download.
    let iso_path = {
        let cached_iso_path = download_fio_test_iso_if_needed()?;
        let iso_path = work_dir_path.join("fio-rig.iso");
        let mut iso_in = File::open(cached_iso_path)?;
        let mut iso_out = File::create(&iso_path)?;
        std::io::copy(&mut iso_in, &mut iso_out)?;
        iso_out.flush()?;
        iso_path
    };

    vm_config["main"]["name"] = value(vm_name);
    vm_config["main"]["cpus"] = value(cpu_cores as i64);
    vm_config["main"]["bootrom"] = value(bootrom_path.as_str());
    vm_config["main"]["memory"] = value(memory as i64);

    vm_config["block_dev"]["boot_iso"]["path"] = value(iso_path.as_str());

    // Specify the Downstairs definition
    vm_config["block_dev"]["test_disk"]["block_size"] = value(disk.block_size as i64);
    vm_config["block_dev"]["test_disk"]["blocks_per_extent"] = value(disk.blocks_per_extent as i64);
    vm_config["block_dev"]["test_disk"]["extent_count"] = value(disk.extent_count as i64);

    // for our testing purposes this can be anything as long as it's mostly
    // monotonic
    vm_config["block_dev"]["test_disk"]["generation"] = value(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    );

    let addrs: Array = disk.ds_addrs.iter().map(|addr| addr.to_string()).collect();
    vm_config["block_dev"]["test_disk"]["targets"] = value(addrs);

    let config_file_path = work_dir_path.join(format!("{}.propolis.toml", vm_name));
    {
        File::create(&config_file_path)?.write_all(vm_config.to_string().as_bytes())?;
    }

    // Im thinking bundle the bootrom in the executable and write it to a file

    let mut propolis_proc = Command::new(propolis_exe)
        .current_dir(work_dir_path)
        .arg(&config_file_path)
        .stderr(Stdio::piped())
        .spawn()?;

    // Give it time to create the tty.
    {
        let (tx, rx) = mpsc::channel();
        let mut propolis_stderr = BufReader::new(propolis_proc.stderr.take().unwrap());
        // this thread will look for "Waiting for a connection to ttya", and
        // then go on to just forward stderr to the process stderr forever.
        thread::spawn(move || -> Result<()> {
            let mut line = String::new();
            while propolis_stderr.read_line(&mut line)? > 0 {
                std::io::stderr().write_all(line.as_bytes())?;
                if line.contains("Waiting for a connection to ttya") {
                    tx.send(())?;
                    break;
                }
                line.clear();
            }
            while propolis_stderr.read_line(&mut line)? > 0 {
                std::io::stderr().write_all(line.as_bytes())?;
                line.clear();
            }
            Ok(())
        });
        // Timeouts, timeouts...
        rx.recv_timeout(Duration::from_secs(60))
            .context("waiting for propolis to say ttya is ready")?;
    }

    // ttya should exist.
    let tty_socket_path = work_dir_path.join("ttya");
    if !tty_socket_path.exists() {
        // something is busted
        propolis_proc.kill()?;
        bail!("couldn't find ttya, maybe propolis didn't run right?");
    }
    let stream = UnixStream::connect(&tty_socket_path).unwrap();

    Ok((propolis_proc, stream))
}

fn destroy_bhyve_vm(vm_name: &str) -> Result<()> {
    // Check that file exists before trying to destroy it. If it doesn't the
    // VM is already gone.
    if !Utf8PathBuf::from_str("/dev/vmm")
        .unwrap()
        .join(vm_name)
        .exists()
    {
        return Ok(());
    }

    let exit = Command::new("bhyvectl")
        .arg(&format!("--vm={}", vm_name))
        .arg("--destroy")
        .spawn()?
        .wait()?;
    ensure!(exit.success());
    Ok(())
}

fn run_fio_tests_on_rig(
    fio_jobs: Vec<FioTestDefinition>,
    mut rig_serial: UnixStream,
) -> Result<Vec<Result<FioTestResult, FioTestErr>>> {
    // Wait for complete alignment sequence. We need this to skip over any
    // bootloader crud before the other end starts running.
    {
        // Scan through so we look at a [ segment ] the length of the alignment buffer.
        // One character goes in, one comes back out
        // 0   1   2   <-[ 3 4 5 6 7 ]<-   8   9   A
        let mut scanning_buffer = VecDeque::new();

        // Initiallize with zeroes matching the expected message length
        for _ in ALIGNMENT_SEQUENCE.iter() {
            scanning_buffer.push_back(0u8);
        }

        // We need to implement a timeout for when we declare the VM as failed.
        let start_time = Instant::now();

        // This is just the timeout for reading a byte so that we can keep
        // checking our overall timeout.
        rig_serial.set_read_timeout(Some(Duration::from_secs(1)))?;

        // Until we've read the alignment sequence, read one byte at a time.
        while !scanning_buffer.iter().eq(ALIGNMENT_SEQUENCE.iter()) {
            // TODO I'm commenting this out for now to avoid polluting stderr in
            // CI but we should turn it back on at log level DEBUG if/when we
            // put slog in.
            // eprintln!("Current alignment buffer holds: {:?}", scanning_buffer);

            let mut byte = [0u8; 1];
            match rig_serial.read(&mut byte) {
                Ok(0) => bail!("Serial stream ended before alignment sequence was found."),
                Ok(1) => {
                    scanning_buffer.push_back(byte[0]);
                    let _ = scanning_buffer.pop_front();
                }
                Ok(_) => unreachable!(),
                Err(e) if e.kind() == ErrorKind::WouldBlock => (), // read timeout, which is fine
                Err(e) if e.kind() == ErrorKind::Interrupted => (), // interrupted, which is fine
                Err(e) => bail!(e),                                // some unexpected error
            }

            // Do timeout check... I dunno, 5 minutes seems like a reasonable
            // time to boot up in, on the extreme?
            let now = Instant::now();
            const TIMEOUT: u64 = 5;
            if now - start_time > Duration::from_secs(TIMEOUT * 60) {
                bail!("VM ran for {} minutes but didn't print the alignment sequence. It's out of touch, and I'm out of time.", TIMEOUT);
            }
        }

        // Alignment completed succesfully!
        eprintln!("Aligned with VM");
    }

    // Run the actual tests. Honestly I don't even feel like using tokio here,
    // but Framed is written around an async runtime. I might end up needing
    // to make everything tokio for ctrl_c handling though later. lol.
    eprintln!("Launching communications with VM");
    let tokio_rt = tokio::runtime::Runtime::new()?;

    // This can technically hang forever, if some things go wrong in some very
    // bad ways. like, the other end panicking kind of going wrong. Not
    // ideal, admittedly. But we can't really know here what a reasonable
    // timeout is because fio tests can take a long while to run, so we're
    // leaving that up to whoever is running this command. /usr/bin/timeout
    // is right there
    let fio_results = tokio_rt.block_on(async move {
        // Make the serial connection async
        let serial_io = tokio::net::UnixStream::from_std(rig_serial)?;

        // Set up the framed serial connection
        let ser_delimited = tokio_util::codec::Framed::new(serial_io, LengthDelimitedCodec::new());
        let fio_rig_codec = MessagePack::<FioRigResponse, FioRigRequest>::default();
        let conn = tokio_serde::Framed::<_, FioRigResponse, FioRigRequest, _>::new(
            ser_delimited,
            fio_rig_codec,
        );
        let (mut conn_write, mut conn_read) = conn.split();

        // Dispatch requests, collect results. I don't want to assume that
        // responses will be one-to-one, even though as written it will be, so
        // I'll send off one task to send stuff, and then read stuff in the main
        // task until the socket shuts down.
        tokio::spawn(async move {
            eprintln!("Entering send loop");
            for test in fio_jobs {
                eprintln!("Sending a test: {}", test.name);
                conn_write.send(FioRigRequest::FioTest(test)).await?;
            }
            conn_write.send(FioRigRequest::Stop).await?;
            let result: Result<_> = Ok(());
            result
        });

        // We'll dump all the fio responses in here
        eprintln!("Entering receive loop");
        let mut fio_results = Vec::new();
        loop {
            let Some(req) = conn_read.next().await else {
                break;
            };

            eprintln!("Received some data: {:?}", req);
            match req? {
                FioRigResponse::FioTestResult(result) => fio_results.push(Ok(result)),
                FioRigResponse::FioTestErr(err) => fio_results.push(Err(err)),
                FioRigResponse::OtherErr(err) => bail!(err), // something went wrong on the server, but not in a test
                FioRigResponse::ShuttingDown => break,
            }
        }

        let result: Result<_> = Ok(fio_results);
        result
    })?;

    // Wait around for things to clean up, but if they don't we don't really
    // care.
    eprintln!("Shutting down comms");
    tokio_rt.shutdown_timeout(Duration::from_secs(10));

    Ok(fio_results)
}

struct DownstairsTrinity {
    ds_addrs: [SocketAddr; 3],
    block_size: u32,
    blocks_per_extent: u32,
    extent_count: u32,
}

/// Launch a set of downstairs using `dsc`. I don't think dsc lets us specify
/// the port to addresses to use, so all the `ds_addrs` in the Downstairs
/// specification will actually be ignored right now. Just make sure they're
/// all 127.0.0.1 on ports 8810, 8820, and 8830
fn launch_downstairs(
    spec: &DownstairsTrinity,
    dsc_exe: &Utf8Path,
    downstairs_exe: &Utf8Path,
    work_dir_path: &Utf8Path,
) -> Result<Child> {
    // For now we naiively assume that if dsc is running _at all_ then it's
    // using the default ports. dsc is only used in testing and almost all our
    // tools run it on the default ports, so it's a better assumption than not
    // checking for anything at all.
    //
    // YYY-F\ It would be nice if we ran this check BEFORE all the compilation,
    // but this is the easiest place to put it right now. maybe what we should
    // do is make a like, check_preconditions kinda function that runs before
    // anything else does. throw the check for vmm in there too
    //
    // TODO is there a better way to do this?
    eprintln!("Checking if anyone else is running dsc...");
    let pgrep_for_downstairs = Command::new("/usr/bin/pgrep").arg("dsc").output()?;
    if pgrep_for_downstairs.status.success() {
        bail!("another dsc is already running - we can't launch downstairs.");
    }
    eprintln!("Nope, we're good!");

    // TODO also make it ensure the downstairs are running before returning.
    // FYI: because this puts the region in work_dir_path, you really need to
    // make sure there's plenty of space there. maybe later we'll split it up
    // into separate paths, but its easier this way.
    let dsc = Command::new(dsc_exe)
        .current_dir(work_dir_path)
        .args([
            "start",
            "--create",
            "--cleanup",
            "--ds-bin",
            downstairs_exe.as_str(),
            "--output-dir",
            work_dir_path.join("dsc-output").as_str(),
            "--region-dir",
            work_dir_path.join("dsc-region").as_str(),
            "--block-size",
            &spec.block_size.to_string(),
            "--extent-size",
            &spec.blocks_per_extent.to_string(),
            "--extent-count",
            &spec.extent_count.to_string(),
        ])
        .spawn()?;
    Ok(dsc)
}

fn shutdown_downstairs(mut dsc_proc: Child, dsc_exe: &Utf8Path) -> Result<()> {
    Command::new(dsc_exe)
        .args(["cmd", "shutdown"])
        .spawn()?
        .wait()?;

    // Wait up to 10 seconds, then move on with our life
    for _ in 0..10 {
        if let Ok(Some(_)) = dsc_proc.try_wait() {
            break;
        }
        sleep(Duration::from_secs(1));
    }

    Ok(())
}
