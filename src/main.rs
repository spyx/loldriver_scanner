mod api;
mod cache;
mod cli;
mod hasher;
mod matcher;
mod report;
mod scanner;

use clap::Parser;
use cli::Cli;
use matcher::Index;
use scanner::{RemoteTarget, ScanOptions};
use std::error::Error;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[-] {e}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    // Fail on a bad --output extension before doing any slow work.
    if let Some(out) = &cli.output {
        let ok = out
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("csv"));
        if !ok {
            return Err("--output must end in .json or .csv".into());
        }
    }

    println!("[*] Initializing LOLDrivers Windows Scanner...");

    let drivers = cache::load_catalog(cli.refresh, cli.offline).await?;
    let index = Index::build(&drivers);
    println!(
        "[+] Indexed {} file names and {} SHA256 hashes.",
        index.name_count(),
        index.hash_count()
    );

    // Ask for the password interactively when only a user name was given.
    let remote = match &cli.remote {
        Some(host) => {
            let password = match (&cli.user, cli.password.clone()) {
                (Some(user), None) => {
                    Some(rpassword::prompt_password(format!("Password for {user}@{host}: "))?)
                }
                (_, pw) => pw,
            };
            Some(RemoteTarget {
                host: host.clone(),
                user: cli.user.clone(),
                domain: cli.domain.clone(),
                password,
            })
        }
        None => None,
    };

    let target = cli.remote.as_deref().unwrap_or("this machine");
    println!("[*] Reading service installs (Event ID 7045) from {target}...");

    let opts = ScanOptions { max: cli.max, days: cli.days, remote };
    let installs = scanner::recent_installs(&opts).map_err(|e| {
        if cli.remote.is_some() {
            format!(
                "{e}\n    Hint: the remote host needs the 'Remote Event Log Management' firewall \
                 rule enabled and an account with Event Log Readers/Administrator rights."
            )
        } else {
            format!("{e}\n    Hint: try running as Administrator.")
        }
    })?;
    let unique = scanner::dedupe(installs);
    println!("[+] {} unique service install(s) found.", unique.len());

    let hits = matcher::find_hits(&index, &unique, cli.remote.as_deref(), !cli.no_verify_hash);
    report::print_console(&hits);

    if let Some(out) = &cli.output {
        report::write_file(out, &hits)?;
    }

    Ok(())
}
