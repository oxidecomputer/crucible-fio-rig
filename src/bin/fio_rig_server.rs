use anyhow::{bail, Result};
use crucible_fio_rig::fio_rig_protocol::{
    FioRigRequest, FioRigResponse, FioTestDefinition, FioTestErr, FioTestResult, ALIGNMENT_SEQUENCE,
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
    let mut ser = SerialStream::open(&tokio_serial::new("/dev/ttyS0", 115200))
        .expect("Failed to open serial port");

    eprintln!("Writing alignment sequence.");
    // Before setting up our framed codec, write an alignment sequence so the
    // other end knows we're in charge of the serial port now.
    ser.write_all(ALIGNMENT_SEQUENCE).await?;
    ser.flush().await?;
    
    let ser_delimited = tokio_util::codec::Framed::new(ser, LengthDelimitedCodec::new());
    let fio_rig_codec = MessagePack::<FioRigRequest, FioRigResponse>::default();
    let mut conn = tokio_serde::Framed::<_, FioRigRequest, FioRigResponse, _>::new(
        ser_delimited,
        fio_rig_codec,
    );

    // Process requests until it's time to shut down
    eprintln!("Entering main loop");
    loop {
        let Some(req) = conn.next().await else {
            break;
        };
        eprintln!("Received a request: {:?}", req);

        match req? {
            FioRigRequest::Stop => {
                // Confirm that we're shutting down
                eprintln!("Shutting down");
                conn.send(FioRigResponse::ShuttingDown).await?;
                break
            },
            FioRigRequest::FioTest(test_def) => {
                eprintln!("Running test.");
                let result = run_fio_test(&test_def).await;
                let response = match result {
                    Ok(result) => FioRigResponse::FioTestResult(result),
                    Err(err) => FioRigResponse::FioTestErr(FioTestErr {
                        id: test_def.id,
                        name: test_def.name,
                        err: err.to_string(),
                    }),
                };
                eprintln!("Sending test results.");
                conn.send(response).await?;
            }
        }
    }

    eprintln!("Closing connection");
    conn.close().await?;

    Ok(())
}

async fn run_fio_test(test_def: &FioTestDefinition) -> Result<FioTestResult> {
    let fio_workdir = tempdir()?;
    let fio_workdir_path = Utf8Path::from_path(fio_workdir.path()).unwrap();

    let fio_job_path = fio_workdir_path.join("job.fio");
    let fio_output_path = fio_workdir_path.join("fio_output");

    // Write the jobfile
    eprintln!("Writing jobfile.");
    {
        let mut job_file = File::create(&fio_job_path).await?;
        job_file
            .write_all(test_def.fio_job.as_bytes())
            .await?;
        job_file.shutdown().await?;
    }

    // Run fio
    eprintln!("Running FIO test.");
    eprintln!("Input: {}\nOutput: {}", fio_job_path, fio_output_path);
    eprintln!("Request: {:?}", test_def);
    let fio_output = Command::new("fio")
        .arg("--filename=/dev/nvme0n1")
        .arg(&format!("--output={}", fio_output_path))
        .args(&test_def.fio_args)
        .arg(&fio_job_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?;

    eprintln!("FIO test done.");
    if !fio_output.status.success() {
        bail!(
            "Fio exited with error code {:?}, here's the output:\n{}",
            fio_output.status.code(),
            String::from_utf8_lossy(&fio_output.stderr)
        );
    }

    // Read the output file
    eprintln!("Reading FIO output.");
    let mut output_file = File::open(fio_output_path).await?;
    let mut results = String::new();
    output_file.read_to_string(&mut results).await?;

    Ok(FioTestResult {
        id: test_def.id,
        name: test_def.name.clone(),
        results,
    })
}
