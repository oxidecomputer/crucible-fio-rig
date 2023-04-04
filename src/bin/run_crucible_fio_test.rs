use std::{
    fmt::format,
    fs::File,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::mpsc,
    thread,
    time::Duration,
};
use argh::FromArgs;
use anyhow::{bail, ensure, anyhow, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cargo_edit::LocalManifest;
use tempfile;
use toml_edit::{value, Document, Item, Value};

// hashes here are blake3, generate with b3sum from `cargo install b3sum`
const BOOTROM_DOWNLOAD_URL: &str = "https://oxide-omicron-build.s3.amazonaws.com/OVMF_CODE_20220922.fd";
const BOOTROM_HASH: &str = "fbeb0d100f8e8bbe12c558806c1ad0d8a88abf7a818eb04ef92498d61d31e2a4";
const ISO_DOWNOLAD_URL: &str = "";
const ISO_HASH: &str = "";


const CACHE_DIR: &str = "/var/cache/crucible-propolis-fio-test";
const BOOTROM_FILENAME: &str = "OVMF_CODE.fd";


#[derive(FromArgs, PartialEq, Debug)]
/// Build propolis with a given commit hash of crucible, and run some fio tests in a VM on it.
struct RunCrucibleFioTestCmd {
    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/crucible.git\")"
    )]
    /// repo url of crucible to use for upstairs/downstairs, defaults to github oxidecomputer/crucible
    crucible_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of crucible to use for upstairs/downstairs
    crucible_commit: String,

    #[argh(
        option,
        default = "String::from(\"https://github.com/oxidecomputer/propolis.git\")"
    )]
    /// repo url of propolis to use for upstairs/downstairs, defaults to github oxidecomputer/propolis
    propolis_url: String,

    #[argh(option)]
    /// commit hash, branch, or tag of propolis to check out
    propolis_commit: String,

    #[argh(positional)]
    /// fio job files on disk that should be sent to the VM to execute.
    fio_jobs: Vec<String>
}

pub fn main() -> Result<()> {
    let cmd: RunCrucibleFioTestCmd = argh::from_env();
    cmd_main(&cmd.crucible_url, &cmd.crucible_commit, &cmd.propolis_url, &cmd.propolis_commit)
}

pub fn cmd_main(
    crucible_url: &str,
    crucible_gitref: &str,
    propolis_url: &str,
    propolis_gitref: &str,
) -> Result<()> {
    // work dir in tmpfs
    let work_dir = tempfile::tempdir()?;

    // create cache dir
    std::fs::create_dir_all(CACHE_DIR)?;

    let work_dir_path = Utf8Path::from_path(work_dir.path())
        .unwrap_or_else(|| panic!("tfw your filepath isn't valid UTF-8: {:?}", work_dir.path()));

    // TODO check for bhyve

    let crucible_dir = work_dir_path.join("crucible");
    let propolis_dir = work_dir_path.join("propolis");

    // Check out the repositories
    clone_and_checkout(crucible_url, crucible_gitref, &crucible_dir)?;
    clone_and_checkout(propolis_url, propolis_gitref, &propolis_dir)?;

    // Modify propolis to use adjacent crucible
    {
        let mut manifest = LocalManifest::try_new(propolis_dir.join("Cargo.toml").as_std_path())?;
        let propolis_deps = manifest
            .get_workspace_dependency_table_mut()
            .expect("Hey why doesn't propolis have workspace dependencies?");

        for (dep_name, subpath) in [
            ("crucible", "upstairs"),
            ("crucible-client-types", "crucible-client-types"),
        ] {
            let dep = propolis_deps
                .get_mut(dep_name)
                .unwrap_or_else(|| panic!("workspace deps don't include {}", dep_name))
                .as_table_mut()
                .unwrap_or_else(|| panic!("workspace dep {} isn't a table", dep_name));
            dep.clear();
            dep["path"] = value(crucible_dir.join(subpath).to_string());
        }
        manifest.write()?;
    }

    // Build crucible downstairs
    let exit = Command::new("cargo")
        .current_dir(&crucible_dir)
        .args(["build", "--release", "-p", "crucible-downstairs"])
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    // Build propolis
    let exit = Command::new("cargo")
        .current_dir(&propolis_dir)
        .args(["build", "--release", "--bin=propolis-standalone"])
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    // Make sure the binaries we need actually exist
    let downstairs_exe = crucible_dir
        .join("target")
        .join("release")
        .join("crucible-downstairs");
    let propolis_exe = propolis_dir
        .join("target")
        .join("release")
        .join("propolis-standalone");
    ensure!(downstairs_exe.exists());
    ensure!(propolis_exe.exists());

    // Run a VM with propolis-standalone
    let vm_name = generate_vm_name()?;
    let (propolis_proc, vm_serial) =
        launch_fio_test_vm(&vm_name, 1, 1024, &propolis_exe, &work_dir_path)?;

    // Connect in with some kind of serial attach thingy
    // copy sercons

    // Run fio
    // TODO: allow user to pass in one or more fio jobs

    // Get the results
    destroy_bhyve_vm(todo!())?;

    Ok(())
}

fn clone_and_checkout<P: AsRef<Path>>(url: &str, gitref: &str, path: &P) -> Result<()> {
    let exit = Command::new("git")
        .arg("clone")
        .arg(url)
        .arg(path.as_ref().as_os_str())
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    let exit = Command::new("git")
        .current_dir(path)
        .arg("checkout")
        .arg(gitref)
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    Ok(())
}

/// Download a file to the path if there isn't already a file there. Make sure
/// the file matches hash.
fn download_if_needed(path: &Utf8Path, url: &str, expected_hash: blake3::Hash) -> Result<()> {
    let check_hash = || -> Result<()> {
        let mut file = File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finalize();
        if hash == expected_hash {
            Ok(())
        } else {
            Err(anyhow!("hash mismatch downloading {} to {}: expected {} but got {}", url, path, expected_hash, hash))
        }
    };

    if path.exists() {
        match check_hash() {
            // File is what we expect!
            Ok(()) => return Ok(()),
            // If the file exists but is the wrong hash, delete and redownload.
            Err(_) => std::fs::remove_file(path)?
        }
    }

    {
        let mut download = reqwest::blocking::get(
            url
        )?;
        let mut file = File::create(path)?;
        download.copy_to(&mut file)?;
        file.flush()?;
    }

    check_hash()
}


/// Download bootrom if its not downloaded, either way return the path to the
/// bootrom.
fn download_bootrom_if_needed() -> Result<Utf8PathBuf> {
    let path = Utf8PathBuf::from(CACHE_DIR).join(BOOTROM_FILENAME);
    // as linked by the readme at https://github.com/oxidecomputer/propolis/
    let url = BOOTROM_DOWNLOAD_URL;
    let expected_hash = blake3::Hash::from_hex(BOOTROM_HASH).unwrap();
    download_if_needed(&path, url, expected_hash).context("Downloading bootrom")?;
    Ok(path)
}

fn download_fio_test_iso_if_needed() -> Result<Utf8PathBuf> {
    todo!()
}

/// generate an unused VM name. This just looks in /dev/vmm to find existing VMs
fn generate_vm_name() -> Result<String> {
    let dev_vmm = Utf8PathBuf::from_str("/dev/vmm").unwrap();

    // This pool doesn't need to be big, it's just for fun. The number we throw
    // on the end is the main thing preventing colissions.
    const DIVINES: [&str; 9] = [
        "DISCOVERY",
        "EMPATHY",
        "GRACE",
        "LIBERTY",
        "ORDER",
        "PATIENCE",
        "PEACE",
        "RIGHTEOUSNESS",
        "VOX",
    ];

    let divine: &str = DIVINES[rand::random::<usize>() % DIVINES.len()];
    let suffix: u128 = rand::random();
    let vm_name = format!("{}{}", divine, suffix);
    let vm_path = dev_vmm.join(&vm_name);
    if vm_path.exists() {
        // normal recursion is fine, chances of colliding even a single time is
        // slim, much less multiple times.
        return generate_vm_name();
    }
    Ok(vm_name)
}

/// Launch a VM with a given name and ISO path. Returns the child process and a
/// serial connection. No networking is provided.
fn launch_fio_test_vm(
    vm_name: &str,
    cpu_cores: u8,
    memory: u32,
    propolis_exe: &Utf8Path,
    work_dir_path: &Utf8Path,
) -> Result<(Child, UnixStream)> {
    // Build the config file
    let base_config_toml = r#"
    [main]

    [block_dev.boot_iso]
    type = "file"

    [block_dev.test_disk]
    type = "file"

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
    let iso_path = download_fio_test_iso_if_needed()?;

    vm_config["main"]["name"] = value(vm_name);
    vm_config["main"]["cpus"] = value(cpu_cores as i64);
    vm_config["main"]["bootrom"] = value(bootrom_path.as_str());
    vm_config["main"]["memory"] = value(memory as i64);

    vm_config["block_dev"]["boot_iso"]["path"] = value(iso_path.as_str());
    vm_config["block_dev"]["test_disk"]["path"] = todo!();

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
    let exit = Command::new("bhyvectl")
        .arg(&format!("--vm={}", vm_name))
        .arg("--destroy")
        .spawn()?
        .wait()?;
    ensure!(exit.success());
    Ok(())
}

fn run_fio_tests(serial_io: UnixStream) -> Result<()> {
    let tokio_rt = tokio::runtime::Runtime::new()?;

    tokio_rt.block_on(async {
        let serial_io = tokio::net::UnixStream::from_std(serial_io)?;

        let result: Result<()> = Ok(());
        result
    })?;

    Ok(())
}
