use crate::matcher::{Hit, Verdict};
use std::error::Error;
use std::fs::File;
use std::path::Path;

fn tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Confirmed => "CONFIRMED",
        Verdict::HashMismatch => "name match, hash differs (likely benign)",
        Verdict::Unverified => "name match, unverified",
    }
}

pub fn print_console(hits: &[Hit]) {
    if hits.is_empty() {
        println!("[+] No known vulnerable drivers found.");
        return;
    }

    println!("\n[!] {} finding(s):", hits.len());
    for h in hits {
        println!("\n  [{}] {}", tag(h.verdict), h.service_name);
        println!("    Path:        {}", h.image_path);
        println!("    Events:      {} (first {}, last {})",
            h.events,
            h.first_seen.as_deref().unwrap_or("?"),
            h.last_seen.as_deref().unwrap_or("?"));
        if let Some(x) = &h.file_sha256 {
            println!("    File SHA256: {x}");
        }
        if let Some(x) = &h.catalog_id {
            println!("    Catalog ID:  {x}");
        }
        if let Some(x) = &h.category {
            println!("    Category:    {x}");
        }
        if let Some(x) = &h.mitre_id {
            println!("    MITRE:       {x}");
        }
        if let Some(x) = h.vendor.as_deref() {
            println!("    Vendor:      {x}");
        }
        if let Some(x) = h.operating_system.as_deref().filter(|d| !d.is_empty()) {
            println!("    OS:          {x}");
        }
        if let Some(x) = h.catalog_created.as_deref() {
            println!("    Added:       {x}");
        }
        if let Some(x) = &h.usecase {
            println!("    Use case:    {x}");
        }
        if let Some(x) = &h.privileges {
            println!("    Privileges:  {x}");
        }
        if let Some(x) = h.description.as_deref().filter(|d| !d.is_empty()) {
            println!("    Details:     {x}");
        }
        if !h.resources.is_empty() {
            println!("    References:  {}", h.resources);
        }
    }
}

/// Writes the findings as JSON or CSV, chosen by the file extension.
pub fn write_file(path: &Path, hits: &[Hit]) -> Result<(), Box<dyn Error>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    match ext.as_deref() {
        Some("json") => serde_json::to_writer_pretty(File::create(path)?, hits)?,
        Some("csv") => {
            let mut w = csv::Writer::from_path(path)?;
            for h in hits {
                w.serialize(h)?;
            }
            w.flush()?;
        }
        _ => return Err("--output must end in .json or .csv".into()),
    }

    println!("[+] Report written to {}", path.display());
    Ok(())
}
