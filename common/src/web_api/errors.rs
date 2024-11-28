use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchesDevicesError {
    pub missing_devices: Vec<u32>,
    pub extra_devices: Vec<u32>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevicesError {
    pub stale_devices: Vec<u32>,
}
