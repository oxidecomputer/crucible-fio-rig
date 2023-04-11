use std::{path::Path, process::Command};

use anyhow::{ensure, Result};
use camino::{Utf8Path, Utf8PathBuf};
use cargo_edit::LocalManifest;
use toml_edit::value;

pub struct BuiltExecutables {
    pub downstairs_exe: Utf8PathBuf,
    pub dsc_exe: Utf8PathBuf,
    pub propolis_standalone_exe: Utf8PathBuf,
}

/// Clones crucible and propolis from the provided URLs. Checks out the
/// specified refs. Modifies propolis to build against the adjacent crucible.
/// Then builds:
/// - crucible-downstairs
/// - dsc
/// - propolis-standalone
///
/// Returns paths to the three executables generated
///
/// code is cloned into `work_dir_path`/crucible and `work_dir_path`/propolis
pub fn build_crucible_and_propolis(
    crucible_url: &str,
    crucible_gitref: &str,
    propolis_url: &str,
    propolis_gitref: &str,
    work_dir_path: &Utf8Path,
) -> Result<BuiltExecutables> {
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

        // dep_name is the name of the dep in propolis' Cargo.toml, and subpath
        // is the subdirectory that crate lives in within the crucible repo
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
        .args([
            "build",
            "--release",
            "-p",
            "crucible-downstairs",
            "-p",
            "dsc",
        ])
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    // Build propolis
    let exit = Command::new("cargo")
        .current_dir(&propolis_dir)
        .args([
            "build",
            "--release",
            "--bin=propolis-standalone",
            "-F",
            "crucible",
        ])
        .spawn()?
        .wait()?;
    ensure!(exit.success());

    // Make sure the binaries we need actually exist
    let downstairs_exe = crucible_dir
        .join("target")
        .join("release")
        .join("crucible-downstairs");
    let dsc_exe = crucible_dir.join("target").join("release").join("dsc");
    let propolis_standalone_exe = propolis_dir
        .join("target")
        .join("release")
        .join("propolis-standalone");
    ensure!(dsc_exe.exists());
    ensure!(downstairs_exe.exists());
    ensure!(propolis_standalone_exe.exists());

    Ok(BuiltExecutables {
        downstairs_exe,
        dsc_exe,
        propolis_standalone_exe,
    })
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
