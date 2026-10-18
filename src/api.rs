use serde::Deserialize;
use std::error::Error;

const LOLDRIVERS_API_URL: &str = "https://www.loldrivers.io/api/drivers.json";

/// One known-vulnerable file (a hash plus metadata) belonging to a catalog entry.
#[derive(Debug, Deserialize, Clone)]
pub struct DriverSample {
    #[serde(rename = "Filename")]
    pub filename: Option<String>,
    #[serde(rename = "OriginalFilename")]
    pub original_filename: Option<String>,
    #[serde(rename = "SHA256")]
    pub sha256: Option<String>,
    #[serde(rename = "Company")]
    pub company: Option<String>,
    #[serde(rename = "Product")]
    pub product: Option<String>,
}

/// The `Commands` object: how the driver is abused.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Commands {
    pub description: Option<String>,
    pub usecase: Option<String>,
    pub privileges: Option<String>,
    pub operating_system: Option<String>,
}

/// One entry of the LOLDrivers catalog.
#[derive(Debug, Deserialize, Clone)]
pub struct LoldriverEntry {
    #[serde(rename = "Id")]
    pub id: Option<String>,
    #[serde(rename = "Category")]
    pub category: Option<String>,
    #[serde(rename = "Created")]
    pub created: Option<String>,
    #[serde(rename = "MitreID")]
    pub mitre_id: Option<String>,
    #[serde(rename = "Tags")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "Resources")]
    pub resources: Option<Vec<String>>,
    #[serde(rename = "Commands")]
    pub commands: Option<Commands>,
    #[serde(rename = "KnownVulnerableSamples")]
    pub known_vulnerable_samples: Option<Vec<DriverSample>>,
}

/// Downloads the raw catalog JSON (kept as bytes so it can be cached untouched).
pub async fn download_catalog() -> Result<Vec<u8>, Box<dyn Error>> {
    println!("[*] Downloading latest LOLDrivers threat feed...");
    let response = reqwest::get(LOLDRIVERS_API_URL).await?.error_for_status()?;
    Ok(response.bytes().await?.to_vec())
}

pub fn parse_catalog(bytes: &[u8]) -> Result<Vec<LoldriverEntry>, serde_json::Error> {
    serde_json::from_slice(bytes)
}
