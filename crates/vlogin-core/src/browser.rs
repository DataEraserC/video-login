//! Browser-driven cookie extraction.
//!
//! This is the fallback that keeps every channel loggable even when the site
//! has no usable headless login API (YouTube, Youku, and anything parked behind
//! a captcha). Instead of speaking the site's login protocol, we hand the user
//! a real browser, let them sign in the ordinary way, and read the resulting
//! cookies back out over the DevTools Protocol.
//!
//! ## Why CDP rather than reading the cookie database
//!
//! The other way (`yt-dlp --cookies-from-browser`) is to open the browser's
//! `Cookies` SQLite file and decrypt each value with a key pulled from the
//! desktop keyring. That costs three more dependencies (SQLite, D-Bus secret
//! service, AES-CBC) and still fails whenever the profile lives on a different
//! machine from the process doing the reading — the normal case for a service
//! like dsh. CDP against a browser we launch ourselves has neither problem.
//!
//! ## Honest limitation
//!
//! We launch the browser **on the machine running this process**. With no
//! display there — a headless server, a container, a remote box — the window is
//! invisible and this method cannot work; use `manual` (paste a cookie file)
//! there. We pass `--headless=new` only when no `$DISPLAY`/`$WAYLAND_DISPLAY` is
//! set, so an SSH session with X forwarding still gets a real window.
//!
//! Secrets boundary: extracted cookies are credentials. They are returned once,
//! handed to the account store, and never written to a log.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::cookies::{self, Cookie};
use crate::error::{Error, Result};

/// Chromium-family binaries, in preference order.
const CHROMIUM_NAMES: &[&str] = &[
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
    "brave",
    "microsoft-edge-stable",
    "microsoft-edge",
];

/// Directories worth checking beyond `$PATH` (macOS app bundles, Nix).
const EXTRA_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
    "/Applications/Google Chrome.app/Contents/MacOS",
    "/Applications/Brave Browser.app/Contents/MacOS",
];

/// A browser we launched and can still talk to / kill.
pub struct BrowserHandle {
    pub pid: u32,
    pub port: u16,
    profile: PathBuf,
    child: Child,
}

impl Drop for BrowserHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// Locate an installed Chromium-family browser.
pub fn find_browser() -> Option<PathBuf> {
    for name in CHROMIUM_NAMES {
        if let Ok(path) = which(name) {
            return Some(path);
        }
        for dir in EXTRA_DIRS {
            let candidate = PathBuf::from(dir).join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve `name` through `$PATH`.
fn which(name: &str) -> Result<PathBuf> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(Error::other(format!("{name} not found in $PATH")))
}

/// Ask the kernel for a free loopback port.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::other(format!("cannot reserve a debugging port: {e}")))?;
    Ok(listener.local_addr()?.port())
}

/// True when a graphical session looks available.
fn has_display() -> bool {
    std::env::var_os("DISPLAY").is_some()
        || std::env::var_os("WAYLAND_DISPLAY").is_some()
        || cfg!(target_os = "macos")
        || cfg!(target_os = "windows")
}

/// Launch a browser on a fresh profile, pointed at `url`.
///
/// A dedicated `--user-data-dir` is deliberate: it sidesteps Chrome's singleton
/// lock on the real profile (which would either fail outright or hand the
/// navigation to an already-running instance that has no debugging port) and it
/// keeps a login for the agent isolated from the user's browsing state.
pub fn launch(url: &str) -> Result<BrowserHandle> {
    let browser = find_browser()
        .ok_or_else(|| Error::other("no Chromium-based browser found; use manual cookie import"))?;
    let port = free_port()?;
    let profile = std::env::temp_dir().join(format!("vlogin-profile-{port}"));

    let mut command = Command::new(browser);
    command
        .arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--no-sandbox")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !has_display() {
        command.arg("--headless=new");
    }
    command.arg(url);

    let child = command
        .spawn()
        .map_err(|e| Error::other(format!("cannot launch the browser: {e}")))?;
    let pid = child.id();
    wait_for_devtools(port)?;
    Ok(BrowserHandle { pid, port, profile, child })
}

/// Poll the DevTools HTTP endpoint until it answers.
fn wait_for_devtools(port: u16) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if http_get(&format!("http://127.0.0.1:{port}/json/version")).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(Error::http("the browser did not expose a DevTools endpoint in time"))
}

/// Websocket URL of the first open page.
fn page_ws_url(port: u16) -> Result<String> {
    let body = http_get(&format!("http://127.0.0.1:{port}/json/list"))?;
    let targets: Vec<serde_json::Value> =
        serde_json::from_str(&body).map_err(|e| Error::http(format!("bad target list: {e}")))?;
    for target in targets {
        if target.get("type").and_then(|v| v.as_str()) == Some("page") {
            if let Some(ws) = target.get("webSocketDebuggerUrl").and_then(|v| v.as_str()) {
                return Ok(ws.to_string());
            }
        }
    }
    Err(Error::http("no browser page is open"))
}

/// Pull the browser's cookies for `hosts`, as Netscape text.
///
/// `hosts` are bare suffixes (`douyin.com`), matched exactly or as a dot
/// suffix — the same rule the channel registry uses to route URLs.
pub fn cookies(port: u16, hosts: &[&str]) -> Result<String> {
    let payload = cdp_call(port, "Network.getAllCookies", serde_json::json!({}))?;
    let list = payload
        .get("cookies")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::http("DevTools returned no cookie list"))?;

    let mut out = Vec::new();
    for entry in list {
        let domain = entry.get("domain").and_then(|v| v.as_str()).unwrap_or_default();
        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        if name.is_empty() || domain.is_empty() {
            continue;
        }
        let bare = domain.trim_start_matches('.');
        if !hosts.iter().any(|h| bare == *h || bare.ends_with(&format!(".{h}"))) {
            continue;
        }
        out.push(Cookie {
            name: name.to_string(),
            value: entry.get("value").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            domain: domain.to_string(),
            path: entry
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string(),
            // A negative or absent `expires` means "session cookie", which the
            // Netscape format encodes as 0.
            expires: entry
                .get("expires")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                .max(0.0) as i64,
            secure: entry.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
            http_only: entry.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
        });
    }
    Ok(cookies::to_netscape(&out, hosts.first().unwrap_or(&"")))
}

/// Close a launched browser and clean up its profile.
pub fn close(mut handle: BrowserHandle) -> Result<()> {
    let _ = handle.child.kill();
    let _ = handle.child.wait();
    let _ = std::fs::remove_dir_all(&handle.profile);
    Ok(())
}

/// Blocking HTTP GET against the loopback DevTools endpoint.
fn http_get(url: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| Error::http(format!("cannot build client: {e}")))?;
    client
        .get(url)
        .send()
        .map_err(|e| Error::http(format!("GET {url} failed: {e}")))?
        .text()
        .map_err(|e| Error::http(format!("cannot read response: {e}")))
}

/// One CDP request, on a fresh connection.
///
/// A new connection per call is deliberate: it keeps this module free of
/// connection state that would have to survive across process invocations, and
/// DevTools allows many concurrent clients. The socket is blocking, so the
/// caller's own deadline is what bounds this.
fn cdp_call(port: u16, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    use tungstenite::{connect, Message};

    let ws_url = page_ws_url(port)?;
    let (mut socket, _) =
        connect(ws_url).map_err(|e| Error::http(format!("cannot reach DevTools: {e}")))?;
    let request = serde_json::json!({ "id": 1, "method": method, "params": params });
    socket
        .send(Message::Text(request.to_string().into()))
        .map_err(|e| Error::http(format!("cannot send DevTools request: {e}")))?;

    loop {
        match socket.read() {
            Ok(Message::Text(text)) => {
                let value: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| Error::http(format!("bad DevTools reply: {e}")))?;
                if value.get("id").and_then(|v| v.as_i64()) != Some(1) {
                    continue; // a CDP event, not our reply
                }
                if let Some(error) = value.get("error") {
                    return Err(Error::http(format!(
                        "DevTools error: {}",
                        error.get("message").and_then(|v| v.as_str()).unwrap_or("unknown")
                    )));
                }
                return Ok(value.get("result").cloned().unwrap_or(serde_json::Value::Null));
            }
            Ok(_) => continue,
            Err(e) => return Err(Error::http(format!("DevTools connection failed: {e}"))),
        }
    }
}

/// Open `url` in a managed browser and wait for cookies to appear.
///
/// This is the `browser` login method: it returns a session whose poll step
/// keeps asking the browser for cookies until the channel's own `check()` says
/// the jar authenticates.
pub fn open(url: &str) -> Result<BrowserHandle> {
    launch(url)
}
