use roxmltree::Document;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::core::{w, Result, HSTRING, PWSTR};
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtOpenSession, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection,
    EvtRender, EvtRenderEventXml, EvtRpcLogin, EvtRpcLoginAuthDefault, EVT_HANDLE, EVT_RPC_LOGIN,
};

/// Owns an event log handle (query, event or session) and closes it when dropped.
struct EvtGuard(EVT_HANDLE);

impl Drop for EvtGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}

/// Where and how to connect when scanning another machine.
pub struct RemoteTarget {
    pub host: String,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub password: Option<String>,
}

pub struct ScanOptions {
    pub max: usize,
    pub days: Option<u32>,
    pub remote: Option<RemoteTarget>,
}

/// A service/driver installation found in the System log (Event ID 7045).
#[derive(Debug, Clone)]
pub struct ServiceInstall {
    pub service_name: String,
    pub image_path: String,
    pub time_created: Option<String>,
}

/// The same service/path seen in one or more events.
#[derive(Debug, Clone)]
pub struct UniqueInstall {
    pub service_name: String,
    pub image_path: String,
    pub count: usize,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// UTF-16, NUL-terminated copy of `s` (what Win32 "wide" APIs expect).
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Opens an RPC session to a remote machine's event log service.
fn open_session(target: &RemoteTarget) -> Result<EvtGuard> {
    // These buffers must stay alive until EvtOpenSession returns: the login
    // struct only holds raw pointers into them.
    let mut server = wide(&target.host);
    let mut user = target.user.as_deref().map(wide);
    let mut domain = target.domain.as_deref().map(wide);
    let mut password = target.password.as_deref().map(wide);

    let ptr = |v: &mut Option<Vec<u16>>| match v {
        Some(buf) => PWSTR(buf.as_mut_ptr()),
        None => PWSTR::null(),
    };

    let login = EVT_RPC_LOGIN {
        Server: PWSTR(server.as_mut_ptr()),
        User: ptr(&mut user),
        Domain: ptr(&mut domain),
        Password: ptr(&mut password),
        Flags: EvtRpcLoginAuthDefault.0 as u32,
    };

    let result = unsafe {
        EvtOpenSession(EvtRpcLogin, &login as *const EVT_RPC_LOGIN as *const c_void, None, None)
    };

    // Don't leave the password lingering in memory longer than needed.
    if let Some(p) = password.as_mut() {
        p.fill(0);
    }

    Ok(EvtGuard(result?))
}

fn open_query(session: Option<&EvtGuard>, days: Option<u32>) -> Result<EvtGuard> {
    let xpath = match days {
        Some(d) => format!(
            "*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= {}]]]",
            d as u64 * 86_400_000
        ),
        None => "*[System[(EventID=7045)]]".to_string(),
    };
    let flags = (EvtQueryChannelPath.0 | EvtQueryReverseDirection.0) as u32;

    let handle = unsafe {
        EvtQuery(session.map(|s| s.0), w!("System"), &HSTRING::from(xpath), flags)?
    };
    Ok(EvtGuard(handle))
}

fn render_xml(event: EVT_HANDLE) -> Result<String> {
    let mut used = 0u32;
    let mut props = 0u32;

    // Call 1: ask how many bytes are needed (fails with ERROR_INSUFFICIENT_BUFFER on purpose)
    unsafe {
        let _ = EvtRender(None, event, EvtRenderEventXml.0 as u32, 0, None, &mut used, &mut props);
    }

    // `used` is in bytes; the buffer holds u16 units
    let mut buf: Vec<u16> = vec![0; (used as usize).div_ceil(2)];
    let buf_bytes = (buf.len() * 2) as u32;

    // Call 2: real call
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0 as u32,
            buf_bytes,
            Some(buf.as_mut_ptr() as *mut _),
            &mut used,
            &mut props,
        )?;
    }

    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf16_lossy(&buf[..len]))
}

fn parse_install(xml: &str) -> Option<ServiceInstall> {
    let doc = Document::parse(xml).ok()?;
    let mut name = None;
    let mut path = None;

    for node in doc.descendants().filter(|n| n.has_tag_name("Data")) {
        match node.attribute("Name") {
            Some("ServiceName") => name = node.text().map(str::to_owned),
            Some("ImagePath") => path = node.text().map(str::to_owned),
            _ => {}
        }
    }

    let time_created = doc
        .descendants()
        .find(|n| n.has_tag_name("TimeCreated"))
        .and_then(|n| n.attribute("SystemTime"))
        .map(str::to_owned);

    Some(ServiceInstall {
        service_name: name?,
        image_path: path?,
        time_created,
    })
}

/// Reads up to `opts.max` of the newest service installs (newest first),
/// from the local machine or from `opts.remote`.
pub fn recent_installs(opts: &ScanOptions) -> Result<Vec<ServiceInstall>> {
    // Declared first, so it is dropped last (after the query that uses it).
    let session = opts.remote.as_ref().map(open_session).transpose()?;
    let results = open_query(session.as_ref(), opts.days)?;
    let mut installs = Vec::new();

    while installs.len() < opts.max {
        let mut handles = [0isize; 16];
        let mut returned = 0u32;

        // Err means no more events (or a real failure); either way we stop
        if unsafe { EvtNext(results.0, &mut handles, 1000, 0, &mut returned) }.is_err() {
            break;
        }

        for &raw in &handles[..returned as usize] {
            let ev = EvtGuard(EVT_HANDLE(raw));
            if let Ok(xml) = render_xml(ev.0) {
                if let Some(install) = parse_install(&xml) {
                    installs.push(install);
                }
            }
        }
    }

    installs.truncate(opts.max);
    Ok(installs)
}

/// Collapses repeated events for the same service + path, counting them.
pub fn dedupe(installs: Vec<ServiceInstall>) -> Vec<UniqueInstall> {
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut out: Vec<UniqueInstall> = Vec::new();

    for i in installs {
        let key = (i.service_name.to_lowercase(), i.image_path.to_lowercase());
        match index.get(&key) {
            Some(&pos) => {
                let u = &mut out[pos];
                u.count += 1;
                // ISO-8601 timestamps sort correctly as plain strings
                if i.time_created < u.first_seen {
                    u.first_seen = i.time_created.clone();
                }
                if i.time_created > u.last_seen {
                    u.last_seen = i.time_created;
                }
            }
            None => {
                index.insert(key, out.len());
                out.push(UniqueInstall {
                    service_name: i.service_name,
                    image_path: i.image_path,
                    count: 1,
                    first_seen: i.time_created.clone(),
                    last_seen: i.time_created,
                });
            }
        }
    }
    out
}
