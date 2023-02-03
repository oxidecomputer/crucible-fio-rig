use serde::{Serialize, Deserialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FioTestDefinition {
    /// Test ID, used to disambiguate tests with the same name (if any). May be sequential
    pub id: u64,

    /// Name of the test
    pub name: String,
    
    /// Contents of a fio file for the test
    pub fio_file_contents: String,

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
    FioTestErr(FioTestErr),
    OtherErr(String)
}