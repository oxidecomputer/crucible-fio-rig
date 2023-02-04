use std::{fmt, error::Error};

use serde::{Serialize, Deserialize};

pub const ALIGNMENT_SEQUENCE: &[u8] = "=== ALIGNTMENT SEQUENCE - ALL SYSTEMS: NOMINAL ===".as_bytes();

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FioTestDefinition {
    /// Test ID, used to disambiguate tests with the same name (if any). May be sequential
    pub id: u64,

    /// Name of the test
    pub name: String,
    
    /// Contents of a fio file for the test
    pub fio_job: String,

    /// Any extra args to be given directly to the fio command
    pub fio_args: Vec<String>
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FioTestResult {
    /// Test ID
    pub id: u64,

    /// Name of the test
    pub name: String,

    /// Raw results of the test
    pub results: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FioTestErr {
    /// Test ID
    pub id: u64,

    /// Name of the test
    pub name: String,

    /// Raw results of the test
    pub err: String,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FioRigRequest {
    FioTest(FioTestDefinition),
    Stop
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FioRigResponse {
    FioTestResult(FioTestResult),
    ShuttingDown,
    FioTestErr(FioTestErr),
    OtherErr(String)
}

impl fmt::Display for FioTestErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error running FIO test {}-{}: {}", self.id, self.name, self.err)
    }
}
impl Error for FioTestErr {}