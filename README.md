# loldriver_scanner

A native Windows scanner written in Rust that detects **vulnerable drivers (BYOVD attacks)**. It reads the Windows Event Log for recently installed drivers and services, then compares them against the [LOLDrivers](https://www.loldrivers.io) threat feed.

> **BYOVD (Bring Your Own Vulnerable Driver):** attackers install a legitimately signed but vulnerable driver to gain kernel-level access and disable security tools. Installing a driver creates a service, and Windows logs that as **Event ID 7045**, so the install leaves a trail this tool can follow.

This project started as a way to learn Rust, covering async HTTP, Serde, Win32 FFI, and error handling. The code is commented and kept small.

## Features

- Downloads the latest LOLDrivers catalog and caches it locally for 24 hours
- Reads **Event ID 7045** (service installed) from the System log through the native Windows Event Log API
- **Verifies the SHA256 of the driver file on disk** against the catalog. This separates real hits from false positives, and also catches renamed files
- Scans **remote machines** with optional explicit credentials
- Collapses repeated events into one finding with a count and first/last seen times
- Enriches findings with catalog details: MITRE ID, vendor, supported OS, use case, privileges, description and references
- Exports findings to **JSON or CSV**
- Time filter (`--days`) and event limit (`--max`)

## Requirements

- Windows 10/11 or Windows Server
- [Rust](https://rustup.rs) (stable, edition 2024 support, so a recent toolchain)
- Administrator rights are recommended. Some event logs and driver files can't be read otherwise.

## Installation

```powershell
git clone https://github.com/spyx/loldriver_scanner.git
cd loldriver_scanner
cargo build --release
```

The binary is `target\release\loldriver_scanner.exe`.

## Usage

```powershell
# Scan this machine (run from an elevated terminal)
cargo run

# Last 30 days only, save a JSON report
cargo run -- --days 30 --output report.json

# Scan a remote machine (prompts for the password)
cargo run -- --remote SERVER01 --user admin --domain CORP

# Use the cached catalog only (no network)
cargo run -- --offline
```

With `cargo run`, arguments after `--` go to the scanner. With the built exe, drop the `cargo run --` part.

### Options

| Option | Description |
|---|---|
| `--remote <HOST>` | Scan the event log of a remote host instead of this machine |
| `--user <USER>` | User for the remote connection (requires `--remote`) |
| `--domain <DOMAIN>` | Domain of the remote user (requires `--user`) |
| `--password <PW>` | Password. If omitted with `--user`, you get a hidden prompt. Prefer the prompt, because command-line passwords end up in shell history |
| `--max <N>` | Maximum number of events to read (default `200`) |
| `--days <N>` | Only events from the last N days |
| `-o, --output <FILE>` | Write the report to a `.json` or `.csv` file |
| `--refresh` | Ignore the cached catalog and download a fresh copy |
| `--offline` | Never use the network; use the cached catalog only |
| `--no-verify-hash` | Skip hashing driver files (name matches stay unverified) |
| `-h, --help` / `-V, --version` | Help and version |

### Example output

```
[*] Initializing LOLDrivers Windows Scanner...
[+] Loaded 702 entries from cache (C:\Users\<you>\AppData\Local\loldriver_scanner\drivers.json).
[+] Indexed 851 file names and 2198 SHA256 hashes.
[*] Reading service installs (Event ID 7045) from this machine...
[+] 122 unique service install(s) found.

[!] 3 finding(s):

  [CONFIRMED] pmxdrv
    Path:        \??\C:\Windows\system32\drivers\pmxdrv.sys
    Events:      1 (first 2026-03-22T13:29:39.0252796Z, last 2026-03-22T13:29:39.0252796Z)
    File SHA256: b1a8ee1222eea5f199028d90b9b77c2acf46d6d84a9e125403b2888c6f681c72
    Catalog ID:  95fc9bf0-ec86-44b3-abad-a4c922aa7742
    Category:    vulnerable driver
    MITRE:       T1068
    Vendor:      Intel Corporation - Intel(R) Management Engine Tools Driver
    OS:          Windows 10, Windows 11
    Added:       2026-06-16
    Use case:    Access privileged kernel or physical-memory primitives through a vulnerable Intel Management Engine Tools driver.
    Privileges:  kernel
    Details:     Intel PMxDrv / pmxdrv64.sys is listed as a KDU provider for Intel Management Engine Tools driver abuse. ...
    References:  https://github.com/hfiref0x/KDU/blob/master/Help/providers.md | ...

  [name match, hash differs (likely benign)] KslD
    Path:        system32\drivers\wd\KslD.sys
    Events:      10 (first 2026-03-22T13:29:39.0180378Z, last 2026-10-15T20:09:02.3895712Z)
    File SHA256: 233a7f7c4886e9f823eaf2860f3cb3c67c2d7665ed8b77b5e67645fec0dafed2
    Catalog ID:  57822c56-6531-4a2e-afbf-96f77dc5fcaf
    Category:    vulnerable driver
    MITRE:       T1068
    Vendor:      Microsoft Corporation - Microsoft Malware Protection
    ...
```

Long fields are shortened here. The full output includes every field listed in [Verdicts](#verdicts).

## Verdicts

Each finding has one of three verdicts:

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | The SHA256 of the file on disk is in the catalog. Treat this as a real vulnerable driver. |
| `name match, hash differs` | The file name is in the catalog but the file on disk is a different build. Often benign. For example, Microsoft's own `KslD.sys` is listed because it can be abused, but a patched version differs. |
| `name match, unverified` | The file name matches but the file couldn't be hashed (missing, no access, or `--no-verify-hash`). Check it manually. |

**A confirmed finding means the driver is known to be vulnerable, not that you were attacked.** Many entries are legitimate drivers from real vendors, such as Intel or Microsoft, that old or unpatched versions can abuse. Check whether the driver is expected on the machine, and update or remove it if not.

The catalog fields behind each finding (ID, category, MITRE ID, vendor, OS, date added, use case, privileges, description and references) come straight from LOLDrivers.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The scan completed (with or without findings) |
| `2` | An error occurred (network, RPC, bad arguments, and so on) |

## Remote scanning

The `--remote` option opens an RPC session to the remote Event Log service. The remote host needs:

- The **Remote Event Log Management** firewall rule enabled
- An account in **Administrators** or **Event Log Readers**

Driver files on the remote host are hashed through admin shares (`\\HOST\C$` and `\\HOST\ADMIN$`). That access uses **your current Windows login**, not the credentials passed with `--user`. If the admin shares aren't reachable, findings fall back to `name match, unverified`.

## How it works

```
LOLDrivers API --> cache (24h) --> index (names + SHA256)
                                          |
Event Log (ID 7045) --> parse XML --> dedupe --> match --> report (console / JSON / CSV)
                                                   ^
                                  hash driver file on disk
```

| File | Role |
|---|---|
| [src/main.rs](src/main.rs) | Entry point: load catalog, scan, match, report |
| [src/cli.rs](src/cli.rs) | Command-line arguments (clap) |
| [src/api.rs](src/api.rs) | Download and parse the LOLDrivers catalog (reqwest, serde) |
| [src/cache.rs](src/cache.rs) | 24-hour local catalog cache |
| [src/scanner.rs](src/scanner.rs) | Windows Event Log queries, remote sessions, XML parsing, dedupe |
| [src/matcher.rs](src/matcher.rs) | Path normalization, catalog index, verdicts |
| [src/hasher.rs](src/hasher.rs) | Streaming SHA256 of files |
| [src/report.rs](src/report.rs) | Console, JSON and CSV output |

Technical notes:

- Event logs are read with the native Windows Event Log API (`EvtQuery`, `EvtNext`, `EvtRender`) through the [`windows`](https://crates.io/crates/windows) crate. Handles are wrapped in a small RAII type so they are always closed.
- Windows APIs use UTF-16 strings, so Rust strings are converted at the FFI boundary.
- Service image paths come in several forms (`\??\C:\...`, `system32\drivers\...`, quoted paths with arguments), and `matcher.rs` normalizes them.

## Development

```powershell
cargo build          # debug build
cargo test           # unit tests (path normalization and resolution)
cargo run -- --help  # list all options
```

Where the catalog is cached: `%LOCALAPPDATA%\loldriver_scanner\drivers.json`.

## Roadmap

Ideas for future versions:

- [ ] **Watch mode:** subscribe to new Event ID 7045 events (`EvtSubscribe`) and alert as they happen
- [ ] **Registry scan:** read `HKLM\SYSTEM\CurrentControlSet\Services` to find drivers installed now, not just those in the log
- [ ] **More event sources:** Sysmon Event 6 (driver loads, includes hashes) and Security Event 4697
- [ ] **Folder scan:** hash a folder of `.sys` files and compare against the catalog
- [ ] **Multi-host scan:** scan many hosts in parallel from a list file
- [ ] **Blocklist and HVCI checks:** check the Microsoft vulnerable driver blocklist and the HVCI state
- [ ] **Alerts:** send findings via webhook, Slack or Windows toast notification

## Limitations

- Only covers drivers that were installed as services and logged as Event ID 7045. Drivers that were already present, or that were installed with logging disabled or the log cleared, will not appear.
- Windows event logs roll over, so old installs may be gone.
- Matching depends on the LOLDrivers catalog being complete and current.
- Windows only.

## Disclaimer

This is a learning project and a detection aid, not a replacement for EDR or a full security assessment. Only scan systems you own or are authorized to assess.

## Credits

Threat data from the [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) project and [loldrivers.io](https://www.loldrivers.io).
