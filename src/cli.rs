use clap::Parser;
use std::path::PathBuf;

/// Detects known-vulnerable (BYOVD) drivers by comparing Windows service-install
/// events (ID 7045) with the LOLDrivers catalog.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    /// Scan the event log of this remote host instead of the local machine
    #[arg(long)]
    pub remote: Option<String>,

    /// User name for the remote connection (prompts for the password if --password is omitted)
    #[arg(long, requires = "remote")]
    pub user: Option<String>,

    /// Domain of the remote user
    #[arg(long, requires = "user")]
    pub domain: Option<String>,

    /// Password for the remote user (visible in shell history; prefer the prompt)
    #[arg(long, requires = "user")]
    pub password: Option<String>,

    /// Maximum number of events to read
    #[arg(long, default_value_t = 200)]
    pub max: usize,

    /// Only look at events from the last N days
    #[arg(long)]
    pub days: Option<u32>,

    /// Write the report to a file (.json or .csv)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Ignore the cached catalog and download a fresh copy
    #[arg(long)]
    pub refresh: bool,

    /// Never touch the network; use the cached catalog only
    #[arg(long, conflicts_with = "refresh")]
    pub offline: bool,

    /// Do not hash driver files on disk (name matches stay unverified)
    #[arg(long)]
    pub no_verify_hash: bool,
}
