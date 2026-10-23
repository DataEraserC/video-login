//! `vlogin-core` — harness-independent, multi-channel video-site login.
//!
//! The crate answers one question: **given a video site and a login method,
//! produce a cookie jar that authenticates a download.** It knows nothing about
//! DeepSeek Harness, cordis, or any agent framework. The plugin
//! (`dsh-video-fetch`) is a thin shell over it.
//!
//! ## The two dimensions
//!
//! * **channel** — the site (`bilibili`, `douyin`, `youtube`, `tencent`,
//!   `iqiyi`, `youku`, plus `generic` for everything else).
//! * **method** — how the credential is obtained (`qr`, `manual`, `sms`,
//!   `password`, `browser`). Each channel advertises the full enum with
//!   `implemented: false` where it has no support, so a host can render a
//!   complete picker and get a structured refusal rather than a missing
//!   capability.
//!
//! ## The account pool
//!
//! A channel holds many accounts, any of which may have been captured by any
//! method. One is pinned as active; the rest are the rotation fallback when a
//! download is rejected. Cookies never leave the store except through
//! [`Hub::export`] / [`Hub::materialize`], which feed a downloader directly.
//!
//! ## Secrets boundary
//!
//! Cookie text and `Set-Cookie` lines are credentials. Throughout this crate:
//!
//! * errors carry status codes and truncated bodies, never cookie values;
//! * the safe projection for display is [`AccountView`], which carries a cookie
//!   *count* and no values;
//! * account and session files are written 0600 inside 0700 directories.

pub mod browser;
pub mod channels;
pub mod cookies;
pub mod error;
pub mod http;
pub mod model;
pub mod session;
pub mod store;
pub mod util;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::error::{Error, Result};
pub use crate::model::{
    AccountStatus, AccountView, Challenge, ChannelInfo, MethodInfo, MethodKind, Poll,
};
pub use crate::store::Store;
use crate::{
    channels::Provider,
    session::Session,
};

/// Every registered channel, in picker order.
pub fn registry() -> Vec<Arc<dyn Provider>> {
    vec![
        channels::bilibili::Bilibili::new(),
        channels::douyin::Douyin::new(),
        channels::youtube::YouTube::new(),
        channels::tencent::Tencent::new(),
        channels::iqiyi::IQiyi::new(),
        channels::youku::Youku::new(),
        channels::generic::Generic::new(),
    ]
}

/// A login request from a host.
#[derive(Debug, Clone, Deserialize)]
pub struct StartRequest {
    pub channel: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub label: Option<String>,
}

/// What the host renders while a login is in flight.
#[derive(Debug, Clone, Serialize)]
pub struct StartResponse {
    pub session_id: String,
    pub challenge: Challenge,
}

/// The state of a login after a `poll` or `submit`.
#[derive(Debug, Clone, Serialize)]
pub struct PollResponse {
    pub result: Poll,
    /// Present once the credential is stored.
    pub account: Option<AccountView>,
}

/// One channel's pool plus a pointer to the pinned account.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelStatus {
    pub channel: ChannelInfo,
    pub accounts: Vec<AccountView>,
    pub active: Option<String>,
}

/// The facade. Every method maps 1:1 onto a CLI subcommand and an ABI op, so
/// there is a single surface to document and test.
pub struct Hub {
    store: Store,
    providers: HashMap<String, Arc<dyn Provider>>,
    order: Vec<String>,
}

impl Hub {
    /// Open a hub rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let providers = registry();
        let order = providers.iter().map(|p| p.info().id.to_string()).collect();
        let map = providers
            .into_iter()
            .map(|p| (p.info().id.to_string(), p))
            .collect::<HashMap<_, _>>();
        Ok(Self { store: Store::new(root), providers: map, order })
    }

    /// Open a hub at the default state root.
    pub fn open_default() -> Result<Self> {
        let root = store::default_root();
        Self::open(root)
    }

    /// State root.
    pub fn root(&self) -> &std::path::Path {
        self.store.root()
    }

    /// All channels, in picker order. `generic` is last so real sites win the
    /// URL routing too.
    pub fn channels(&self) -> Vec<ChannelInfo> {
        self.order.iter().filter_map(|id| self.providers.get(id).map(|p| p.info())).collect()
    }

    /// Advertised channels without `generic`, which is a fallback rather than a
    /// site a user would pick.
    pub fn site_channels(&self) -> Vec<ChannelInfo> {
        self.channels().into_iter().filter(|c| c.id != "generic").collect()
    }

    fn provider(&self, channel: &str) -> Result<&Arc<dyn Provider>> {
        self.providers
            .get(channel)
            .ok_or_else(|| Error::channel(format!(
                "unknown channel '{channel}'; known channels: {}",
                self.order.join(", ")
            )))
    }

    /// Begin an interactive login (QR, SMS, password).
    pub fn start(&self, request: &StartRequest) -> Result<StartResponse> {
        let provider = self.provider(&request.channel)?;
        let (challenge, state) = provider.start(&request.method, &request.params)?;
        let mut session = Session::create(&request.channel, &request.method, state);
        if let Some(label) = &request.label {
            channels::state_set(&mut session, "label", Value::String(label.clone()));
        }
        session.save(&self.store.session_dir())?;
        Ok(StartResponse { session_id: session.id.clone(), challenge })
    }

    /// Begin a browser-driven login: open the site in a managed browser and
    /// wait for the user to sign in.
    pub fn browse(&self, channel: &str) -> Result<StartResponse> {
        let provider = self.provider(channel)?;
        let info = provider.info();
        let url = if info.login_url.is_empty() {
            return Err(Error::channel(format!(
                "channel '{channel}' has no login page to open; import cookies instead"
            )));
        } else {
            info.login_url
        };
        channels::require_method(&info, "browser")?;
        let handle = browser::launch(url)?;
        let state = channels::state_of(&[
            ("pid", Value::from(handle.pid)),
            ("port", Value::from(handle.port)),
            ("hosts", serde_json::to_value(&info.hosts)?),
            ("jar", Value::String(String::new())),
        ]);
        let session = Session::create(channel, "browser", state);
        session.save(&self.store.session_dir())?;
        // Keep the child process alive for the lifetime of the session: the
        // handle is dropped here, which would kill it, so leak it deliberately
        // and let the pid/port be the only record. The browser exits when the
        // user closes the window; `close_session` kills it by pid.
        std::mem::forget(handle);
        Ok(StartResponse {
            session_id: session.id.clone(),
            challenge: Challenge::Browse {
                url: url.to_string(),
                prompt: "已打开浏览器，请在其中完成登录后回到这里".into(),
            },
        })
    }

    /// Advance a login that needs no further input.
    pub fn poll(&self, session_id: &str) -> Result<PollResponse> {
        let dir = self.store.session_dir();
        let mut session = Session::load(&dir, session_id)?
            .ok_or_else(|| Error::channel("that login session has expired; start again"))?;

        if session.method == "browser" {
            return self.poll_browser(&mut session);
        }

        let provider = self.provider(&session.channel)?;
        let result = provider.poll(&mut session)?;
        session.save(&dir)?;
        self.finish(&mut session, result)
    }

    /// Advance a login with user-supplied input.
    pub fn submit(&self, session_id: &str, params: &Value) -> Result<PollResponse> {
        let dir = self.store.session_dir();
        let mut session = Session::load(&dir, session_id)?
            .ok_or_else(|| Error::channel("that login session has expired; start again"))?;
        let provider = self.provider(&session.channel)?;
        let result = provider.submit(&mut session, params)?;
        session.save(&dir)?;
        self.finish(&mut session, result)
    }

    /// Pull cookies out of the browser we launched for `session`.
    fn poll_browser(&self, session: &mut Session) -> Result<PollResponse> {
        let dir = self.store.session_dir();
        let port = session
            .state
            .get("port")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::channel("this browser session has no debugging port"))?
            as u16;
        let hosts: Vec<String> = session
            .state
            .get("hosts")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
            })
            .unwrap_or_default();
        let host_refs: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();

        match browser::cookies(port, &host_refs) {
            Ok(cookies) if cookies::count_netscape_cookies(&cookies) > 0 => {
                let provider = self.provider(&session.channel)?;
                let identity = provider
                    .check(&cookies)
                    .map(|outcome| outcome.identity)
                    .unwrap_or_default();
                session.save(&dir)?;
                self.finish(
                    session,
                    Poll::Done { cookies, identity },
                )
            }
            Ok(_) => Ok(PollResponse {
                result: Poll::Pending { message: "等待在浏览器中完成登录…".into() },
                account: None,
            }),
            Err(error) => Ok(PollResponse {
                // A browser that has not finished starting (or that the user
                // closed) is a normal interim state, not a failure.
                result: Poll::Pending { message: error.to_string() },
                account: None,
            }),
        }
    }

    /// Store a completed login, or hand back the in-flight session untouched.
    pub fn finish(&self, session: &mut Session, result: Poll) -> Result<PollResponse> {
        match result {
            Poll::Done { cookies, identity } => {
                let label = channels::state_str(session, "label");
                let view = self.store.upsert(
                    &session.channel,
                    &session.method,
                    &cookies,
                    &identity,
                    &label,
                )?;
                Session::remove(&self.store.session_dir(), &session.id)?;
                Ok(PollResponse {
                    result: Poll::Done { cookies, identity },
                    account: Some(view),
                })
            }
            other => Ok(PollResponse { result: other, account: None }),
        }
    }

    /// Import a finished credential (a pasted cookie file or header).
    pub fn import(
        &self,
        channel: &str,
        method: &str,
        cookies_text: &str,
        label: &str,
    ) -> Result<AccountView> {
        let provider = self.provider(channel)?;
        let info = provider.info();
        if method != "manual" {
            channels::require_method(&info, method)?;
        }
        let normalized = channels::normalize_import(cookies_text, info.cookie_domain)?;
        let identity = provider
            .check(&normalized)
            .map(|outcome| outcome.identity)
            .unwrap_or_default();
        self.store.upsert(channel, method, &normalized, &identity, label)
    }

    /// Probe one account and record the result. Omit `account_id` to probe the
    /// pinned account.
    pub fn status(&self, channel: &str, account_id: Option<&str>) -> Result<AccountView> {
        let provider = self.provider(channel)?;
        let account = match account_id {
            Some(id) => self.store.get(channel, id)?,
            None => self.store.active(channel)?,
        };
        let status = match provider.check(&account.cookies) {
            Ok(outcome) if outcome.logged_in => AccountStatus::Active,
            Ok(_) => AccountStatus::Expired,
            Err(_) => AccountStatus::Unreachable,
        };
        let mut view = account.view();
        view.status = status;
        self.store.record_check(channel, &account.id, status)?;
        Ok(view)
    }

    /// Every account of a channel, pinned first.
    pub fn accounts(&self, channel: &str) -> Result<Vec<AccountView>> {
        self.provider(channel)?;
        self.store.list(channel)
    }

    /// Status of every channel, for a full dashboard render.
    pub fn statuses(&self) -> Vec<ChannelStatus> {
        self.site_channels()
            .into_iter()
            .map(|channel| ChannelStatus {
                active: self.store.load(&channel.id).ok().and_then(|f| f.active),
                accounts: self.store.list(&channel.id).unwrap_or_default(),
                channel,
            })
            .collect()
    }

    /// Pin an account as the channel's credential.
    pub fn pin(&self, channel: &str, account_id: &str) -> Result<AccountView> {
        self.provider(channel)?;
        self.store.pin(channel, account_id)
    }

    /// Log out of one account (drop its cookies).
    pub fn logout(&self, channel: &str, account_id: &str) -> Result<bool> {
        self.provider(channel)?;
        self.store.remove(channel, account_id)
    }

    /// Drop every account of a channel.
    pub fn clear(&self, channel: &str) -> Result<usize> {
        self.provider(channel)?;
        self.store.clear(channel)
    }

    /// Netscape text for one account, to hand to a downloader. SECRET.
    pub fn export(&self, channel: &str, account_id: Option<&str>) -> Result<String> {
        self.provider(channel)?;
        match account_id {
            Some(id) => self.store.cookies_for(channel, id),
            None => Ok(self.store.active(channel)?.cookies),
        }
    }

    /// Write one account's cookies to a 0600 file and return its path.
    ///
    /// This is what a downloader's `--cookies` flag points at. The file holds
    /// secrets; the path does not.
    pub fn materialize(&self, channel: &str, account_id: Option<&str>) -> Result<PathBuf> {
        self.provider(channel)?;
        match account_id {
            Some(id) => self.store.materialize(channel, id),
            None => {
                let account = self.store.active(channel)?;
                self.store.materialize(channel, &account.id)
            }
        }
    }

    /// Route a URL to its channel, falling back to `generic`.
    pub fn channel_for_url(&self, url: &str) -> Option<String> {
        let host = util::host_of(url)?;
        for id in &self.order {
            if id == "generic" {
                continue;
            }
            if let Some(provider) = self.providers.get(id) {
                if provider
                    .info()
                    .hosts
                    .iter()
                    .any(|h| host == *h || host.ends_with(&format!(".{h}")))
                {
                    return Some(id.clone());
                }
            }
        }
        Some("generic".to_string())
    }

    /// Abandon a login in flight, killing its browser if it owns one.
    pub fn cancel(&self, session_id: &str) -> Result<()> {
        let dir = self.store.session_dir();
        if let Some(session) = Session::load(&dir, session_id)? {
            if let Some(pid) = session.state.get("pid").and_then(|v| v.as_u64()) {
                let _ = kill_pid(pid);
            }
        }
        Session::remove(&dir, session_id)
    }

    /// Delete expired session files.
    pub fn sweep(&self) -> Result<usize> {
        self.store.sweep_sessions(session::DEFAULT_TTL_MS)
    }
}

/// Best-effort process kill by pid.
fn kill_pid(pid: u64) -> Result<()> {
    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .arg(pid.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        // A process that already exited is not an error here.
        let _ = status;
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
    Ok(())
}
