use anyhow::{bail, Result};
use crucible_fio_rig::fio_rig_protocol::{
    FioRigRequest, FioRigResponse, FioTestDefinition, FioTestErr, FioTestResult,
};
use camino::Utf8Path;
use futures::prelude::*;
use std::{process::Stdio, time::Duration};
use tempfile::tempdir;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command, time::sleep,
};
use tokio_serde::formats::MessagePack;
use tokio_serial::SerialStream;
use tokio_util::codec::LengthDelimitedCodec;

#[tokio::main]
async fn main() -> Result<()> {
    // If we get an error we should just turn off early, so ignoring them
    let _ = main_loop().await;

    let _ = Command::new("shutdown").arg("now").spawn()?.wait().await?;

    // Sleep gently as the world falls away
    sleep(Duration::from_secs(0x8861d914ca578b83)).await;

    Ok(())
}

async fn main_loop() -> Result<()> {
    // Attach to TTY
    let ser = SerialStream::open(&tokio_serial::new("/dev/ttyS0", 1500000))
        .expect("Failed to open serial port");
    let ser_delimited = tokio_util::codec::Framed::new(ser, LengthDelimitedCodec::new());
    let fio_rig_codec = MessagePack::<FioRigRequest, FioRigResponse>::default();
    let mut conn = tokio_serde::Framed::<_, FioRigRequest, FioRigResponse, _>::new(
        ser_delimited,
        fio_rig_codec,
    );

    // Process requests until it's time to shut down
    loop {
        let Some(req) = conn.next().await else {
            break;
        };

        match req? {
            FioRigRequest::Stop => break,
            FioRigRequest::FioTest(test_def) => {
                let result = run_fio_test(&test_def).await;
                let response = match result {
                    Ok(result) => FioRigResponse::FioTestResult(result),
                    Err(err) => FioRigResponse::FioTestErr(FioTestErr {
                        id: test_def.id,
                        name: test_def.name,
                        err: err.to_string(),
                    }),
                };
                conn.feed(response).await?;
            }
        }
    }

    conn.close().await?;

    Ok(())
}

async fn run_fio_test(test_def: &FioTestDefinition) -> Result<FioTestResult> {
    let fio_workdir = tempdir()?;
    let fio_workdir_path = Utf8Path::from_path(fio_workdir.path()).unwrap();

    let fio_job_path = fio_workdir_path.join("job.fio");
    let fio_output_path = fio_workdir_path.join("fio_output");

    // Write the jobfile
    {
        let mut job_file = File::create(&fio_job_path).await?;
        job_file
            .write_all(test_def.fio_file_contents.as_bytes())
            .await?;
        job_file.shutdown().await?;
    }

    // Run fio
    let fio_output = Command::new("fio")
        .arg("--filename=") // TODO IO device
        .arg(&format!("--output={}", fio_output_path))
        .args(&test_def.fio_args)
        .arg(&fio_job_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?;

    if !fio_output.status.success() {
        bail!(
            "Fio exited with error code {:?}, here's the output:\n{}",
            fio_output.status.code(),
            String::from_utf8_lossy(&fio_output.stderr)
        );
    }

    // Read the output file
    let mut output_file = File::open(fio_output_path).await?;
    let mut results = String::new();
    output_file.read_to_string(&mut results).await?;

    Ok(FioTestResult {
        id: test_def.id,
        name: test_def.name.clone(),
        results,
    })
}
