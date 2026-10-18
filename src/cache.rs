use crate::api::{self, LoldriverEntry};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

fn cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("loldriver_scanner").join("drivers.json"))
}

fn is_fresh(path: &PathBuf) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < MAX_AGE)
}

/// Loads the catalog from the local cache when possible, otherwise downloads it.
pub async fn load_catalog(
    refresh: bool,
    offline: bool,
) -> Result<Vec<LoldriverEntry>, Box<dyn Error>> {
    let path = cache_path();

    if !refresh {
        if let Some(p) = &path {
            if offline || is_fresh(p) {
                if let Ok(drivers) = fs::read(p).map_err(|e| e.to_string()).and_then(|b| {
                    api::parse_catalog(&b).map_err(|e| e.to_string())
                }) {
                    println!("[+] Loaded {} entries from cache ({}).", drivers.len(), p.display());
                    return Ok(drivers);
                }
            }
        }
    }

    if offline {
        return Err("--offline was set but there is no usable cached catalog".into());
    }

    let bytes = api::download_catalog().await?;
    let drivers = api::parse_catalog(&bytes)?;
    println!("[+] Downloaded {} driver entries.", drivers.len());

    // Caching is best-effort: a failure here must not stop the scan.
    if let Some(p) = &path {
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let Err(e) = fs::write(p, &bytes) {
            eprintln!("[!] Could not write cache: {e}");
        }
    }
    Ok(drivers)
}
