use crate::api::LoldriverEntry;
use crate::hasher;
use crate::scanner::UniqueInstall;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// How sure we are that an install is a known-vulnerable driver.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The file's SHA256 is in the catalog.
    Confirmed,
    /// Same file name as a catalog entry, but the file on disk has a different hash.
    HashMismatch,
    /// Same file name; the file could not be read or hashing was disabled.
    Unverified,
}

/// A finding, flat so it serializes cleanly to both JSON and CSV.
#[derive(Debug, Serialize)]
pub struct Hit {
    pub verdict: Verdict,
    pub service_name: String,
    pub image_path: String,
    pub events: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub file_sha256: Option<String>,
    pub catalog_id: Option<String>,
    pub category: Option<String>,
    pub mitre_id: Option<String>,
    pub catalog_created: Option<String>,
    pub vendor: Option<String>,
    pub operating_system: Option<String>,
    pub usecase: Option<String>,
    pub privileges: Option<String>,
    pub description: Option<String>,
    pub resources: String,
}

/// Lookup tables over the catalog, built once.
pub struct Index<'a> {
    entries: &'a [LoldriverEntry],
    by_name: HashMap<String, Vec<usize>>,
    by_sha256: HashMap<String, usize>,
}

impl<'a> Index<'a> {
    pub fn build(entries: &'a [LoldriverEntry]) -> Self {
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_sha256 = HashMap::new();

        for (i, entry) in entries.iter().enumerate() {
            let mut add_name = |name: &str| {
                if !name.is_empty() {
                    let list = by_name.entry(name.to_lowercase()).or_default();
                    if !list.contains(&i) {
                        list.push(i);
                    }
                }
            };

            for tag in entry.tags.iter().flatten() {
                add_name(tag);
            }
            for s in entry.known_vulnerable_samples.iter().flatten() {
                for name in [&s.filename, &s.original_filename].into_iter().flatten() {
                    add_name(name);
                }
                if let Some(h) = s.sha256.as_deref().filter(|h| !h.is_empty()) {
                    by_sha256.insert(h.to_lowercase(), i);
                }
            }
        }

        Index { entries, by_name, by_sha256 }
    }

    pub fn name_count(&self) -> usize {
        self.by_name.len()
    }

    pub fn hash_count(&self) -> usize {
        self.by_sha256.len()
    }
}

fn strip_prefix_ci<'s>(s: &'s str, prefix: &str) -> Option<&'s str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Extracts just the executable path from a service ImagePath:
/// removes quotes, the `\??\` prefix and trailing arguments.
fn executable_part(raw: &str) -> String {
    let raw = raw.trim();

    let mut p = match raw.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest).to_string(),
        None => raw.to_string(),
    };

    if let Some(rest) = p.strip_prefix(r"\??\") {
        p = rest.to_string();
    }

    // Cut arguments after the file name (e.g. `c:\x.exe -k group`)
    let lower = p.to_ascii_lowercase();
    if let Some(idx) = lower.find(".sys").or_else(|| lower.find(".exe")) {
        p.truncate(idx + 4);
    }
    p
}

/// Lowercase file name of an ImagePath, used for catalog lookups.
pub fn normalize_filename(raw: &str) -> String {
    executable_part(raw)
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_lowercase()
}

/// Turns an ImagePath into a path we can open from this machine.
/// For a remote host, drive paths become admin-share UNC paths (`\\HOST\C$\...`).
pub fn resolve_path(raw: &str, remote: Option<&str>) -> Option<PathBuf> {
    let exe = executable_part(raw);

    // System-relative forms: `\SystemRoot\x`, `system32\drivers\x`
    let system_relative = strip_prefix_ci(&exe, r"\SystemRoot\")
        .or_else(|| strip_prefix_ci(&exe, "system32\\"))
        .map(|rest| {
            if exe.to_ascii_lowercase().starts_with("system32") {
                format!("system32\\{rest}")
            } else {
                rest.to_string()
            }
        });

    if let Some(rest) = system_relative {
        return Some(match remote {
            Some(host) => PathBuf::from(format!(r"\\{host}\ADMIN$\{rest}")),
            None => {
                let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
                PathBuf::from(format!(r"{root}\{rest}"))
            }
        });
    }

    // Drive-letter path: `C:\...`
    let bytes = exe.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && &exe[1..3] == ":\\" {
        return Some(match remote {
            Some(host) => PathBuf::from(format!(r"\\{host}\{}$\{}", &exe[..1], &exe[3..])),
            None => PathBuf::from(exe),
        });
    }

    None
}

/// "Company - Product" from the first sample that has either.
fn vendor_of(entry: &LoldriverEntry) -> Option<String> {
    entry.known_vulnerable_samples.iter().flatten().find_map(|s| {
        let company = s.company.as_deref().filter(|c| !c.is_empty());
        let product = s.product.as_deref().filter(|p| !p.is_empty());
        match (company, product) {
            (Some(c), Some(p)) => Some(format!("{c} - {p}")),
            (Some(x), None) | (None, Some(x)) => Some(x.to_string()),
            (None, None) => None,
        }
    })
}

/// Compares the unique installs with the catalog and returns the findings.
pub fn find_hits(
    index: &Index,
    installs: &[UniqueInstall],
    remote: Option<&str>,
    verify_hash: bool,
) -> Vec<Hit> {
    let mut hits = Vec::new();

    for install in installs {
        let name_matches = index.by_name.get(&normalize_filename(&install.image_path));

        let file_hash = if verify_hash {
            resolve_path(&install.image_path, remote)
                .and_then(|p| hasher::sha256_file(&p).ok())
        } else {
            None
        };

        // Hash match wins (it also catches renamed files); otherwise fall back to the name.
        let (verdict, entry_idx) = match file_hash.as_ref().and_then(|h| index.by_sha256.get(h)) {
            Some(&i) => (Verdict::Confirmed, i),
            None => match name_matches.and_then(|v| v.first()) {
                Some(&i) if file_hash.is_some() => (Verdict::HashMismatch, i),
                Some(&i) => (Verdict::Unverified, i),
                None => continue,
            },
        };

        let entry = &index.entries[entry_idx];
        let cmd = entry.commands.as_ref();

        hits.push(Hit {
            verdict,
            service_name: install.service_name.clone(),
            image_path: install.image_path.clone(),
            events: install.count,
            first_seen: install.first_seen.clone(),
            last_seen: install.last_seen.clone(),
            file_sha256: file_hash,
            catalog_id: entry.id.clone(),
            category: entry.category.clone(),
            mitre_id: entry.mitre_id.clone(),
            catalog_created: entry.created.clone(),
            vendor: vendor_of(entry),
            operating_system: cmd.and_then(|c| c.operating_system.clone()),
            usecase: cmd.and_then(|c| c.usecase.clone()),
            privileges: cmd.and_then(|c| c.privileges.clone()),
            description: cmd.and_then(|c| c.description.clone()),
            resources: entry.resources.iter().flatten().cloned().collect::<Vec<_>>().join(" | "),
        });
    }

    hits.sort_by_key(|h| match h.verdict {
        Verdict::Confirmed => 0,
        Verdict::Unverified => 1,
        Verdict::HashMismatch => 2,
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_from_nt_path() {
        assert_eq!(normalize_filename(r"\??\C:\Windows\system32\drivers\PmxDrv.SYS"), "pmxdrv.sys");
    }

    #[test]
    fn filename_from_quoted_path_with_args() {
        assert_eq!(normalize_filename(r#""C:\Program Files\X\svc.exe" -k group"#), "svc.exe");
    }

    #[test]
    fn filename_from_relative_path() {
        assert_eq!(normalize_filename(r"system32\drivers\wd\KslD.sys"), "ksld.sys");
    }

    #[test]
    fn resolve_local_drive_path() {
        assert_eq!(
            resolve_path(r"\??\C:\Temp\evil.sys", None),
            Some(PathBuf::from(r"C:\Temp\evil.sys"))
        );
    }

    #[test]
    fn resolve_remote_drive_path() {
        assert_eq!(
            resolve_path(r"C:\Temp\evil.sys", Some("srv01")),
            Some(PathBuf::from(r"\\srv01\C$\Temp\evil.sys"))
        );
    }

    #[test]
    fn resolve_remote_relative_path() {
        assert_eq!(
            resolve_path(r"system32\drivers\wd\KslD.sys", Some("srv01")),
            Some(PathBuf::from(r"\\srv01\ADMIN$\system32\drivers\wd\KslD.sys"))
        );
        assert_eq!(
            resolve_path(r"\SystemRoot\system32\drivers\x.sys", Some("srv01")),
            Some(PathBuf::from(r"\\srv01\ADMIN$\system32\drivers\x.sys"))
        );
    }

    #[test]
    fn unknown_form_is_none() {
        assert_eq!(resolve_path("weird", None), None);
    }
}
