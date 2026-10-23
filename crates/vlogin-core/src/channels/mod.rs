//! Channel providers — one module per video site.
//!
//! A provider owns exactly one thing: the HTTP conversation that turns a user
//! action into a set of auth cookies, plus a read-only "am I still logged in"
//! probe. Everything else (codec, storage, pooling, rotation) is generic and
//! lives outside this directory.
//!
//! `channel × method` is the extension seam. The registry advertises the full
//! method enum for every channel, with `implemented: false` for the ones a
//! channel has not got round to, so a host can render a complete picker and get
//! a typed refusal rather than a hole.

use serde_json::Value;

use crate::cookies;
use crate::error::{Error, Result};
use crate::model::{Challenge, ChannelInfo, MethodInfo, Poll};
use crate::session::Session;

pub mod bilibili;
pub mod douyin;
pub mod generic;
pub mod iqiyi;
pub mod tencent;
pub mod youku;
pub mod youtube;

/// Result of a read-only login probe.
pub struct CheckOutcome {
    pub logged_in: bool,
    /// Nickname / channel name reported by the site, when logged in.
    pub identity: String,
}

/// What one video site knows how to do.
///
/// The default `poll` / `submit` bodies produce the structured "this channel
/// does not implement that method" error, so a provider only overrides what it
/// actually supports.
pub trait Provider: Send + Sync {
    /// Advertised capabilities.
    fn info(&self) -> ChannelInfo;

    /// Begin a login. Returns what to render plus the state to persist in the
    /// session.
    fn start(&self, method: &str, params: &Value) -> Result<(Challenge, Value)>;

    /// Advance a login that needs no further input (QR polling, OAuth loopback).
    fn poll(&self, session: &mut Session) -> Result<Poll> {
        Err(unsupported(&self.info(), &session.method))
    }

    /// Advance a login with user-supplied input (SMS code, password).
    fn submit(&self, session: &mut Session, _params: &Value) -> Result<Poll> {
        Err(unsupported(&self.info(), &session.method))
    }

    /// Read-only probe of stored cookies.
    fn check(&self, cookies_text: &str) -> Result<CheckOutcome>;
}

/// Look up a method in a channel's advertised list.
///
/// The returned reference borrows from `info`, not from `method`, so the
/// lifetime is spelled out; with two input references, elision would be
/// ambiguous.
pub fn method_info<'a>(info: &'a ChannelInfo, method: &str) -> Option<&'a MethodInfo> {
    info.methods.iter().find(|m| m.id == method)
}

/// Structured refusal naming the channel, the method, and the web fallback.
///
/// `pub(crate)` so provider modules can reuse the same wording for a method
/// they advertise but do not implement (see the `generic` channel).
pub(crate) fn unsupported(info: &ChannelInfo, method: &str) -> Error {
    match method_info(info, method) {
        Some(m) if !m.implemented => Error::channel(format!(
            "channel '{}' does not implement the '{}' login method; \
             sign in through a browser instead: {}",
            info.id, method, info.login_url
        )),
        Some(_) => Error::channel(format!("channel '{}' cannot handle '{}' here", info.id, method)),
        None => Error::channel(format!(
            "unknown login method '{}'; known methods: {}",
            method,
            crate::model::ALL_METHODS.join(", ")
        )),
    }
}

/// Reject an unknown or unimplemented method before doing any work.
pub fn require_method(info: &ChannelInfo, method: &str) -> Result<()> {
    match method_info(info, method) {
        Some(m) if m.implemented => Ok(()),
        _ => Err(unsupported(info, method)),
    }
}

// ── Session cookie jar ──────────────────────────────────────────────────────
//
// Providers accumulate cookies across several requests: most sites issue a
// fingerprint/device cookie on the first call and the auth cookie only after
// the user confirms. The partial jar therefore lives in the session.

/// The jar accumulated by a session so far, as Netscape text.
pub fn jar_of(session: &Session) -> String {
    session.state.get("jar").and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

/// Replace the session's jar.
pub fn set_jar(session: &mut Session, text: &str) {
    if let Value::Object(map) = &mut session.state {
        map.insert("jar".into(), Value::String(text.to_string()));
    }
}

/// Merge `extra` into the session's jar; `extra` wins on duplicate names.
pub fn merge_jar(session: &mut Session, extra: &str) {
    let merged = merge_netscape(&jar_of(session), extra);
    set_jar(session, &merged);
}

/// A `Cookie:` header built from the session jar. SECRET — for outbound
/// requests only, never for logs or tool results.
pub fn jar_header(session: &Session) -> String {
    cookies::header_from_netscape(&jar_of(session))
}

/// Read a string out of the session's provider state.
pub fn state_str(session: &Session, key: &str) -> String {
    session
        .state
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Write a value into the session's provider state.
pub fn state_set(session: &mut Session, key: &str, value: Value) {
    if let Value::Object(map) = &mut session.state {
        map.insert(key.to_string(), value);
    }
}

// ── Cookie helpers ──────────────────────────────────────────────────────────

/// Turn raw `Set-Cookie` lines into Netscape text for storage.
///
/// Rejects an empty result: a login that issued no cookies did not complete,
/// and storing an empty jar would silently downgrade later downloads to
/// anonymous.
pub fn harvest(set_cookies: &[String], fallback_domain: &str) -> Result<String> {
    let parsed = cookies::parse_set_cookies(set_cookies);
    if parsed.is_empty() {
        return Err(Error::cookie(format!(
            "no cookies were issued for {fallback_domain}; the login did not complete"
        )));
    }
    Ok(cookies::to_netscape(&parsed, fallback_domain))
}

/// Merge two Netscape texts, with `extra` winning on duplicate names.
pub fn merge_netscape(base: &str, extra: &str) -> String {
    let mut out: Vec<cookies::Cookie> = cookies::parse_netscape(extra);
    for cookie in cookies::parse_netscape(base) {
        if !out.iter().any(|c| c.name == cookie.name && c.domain == cookie.domain) {
            out.push(cookie);
        }
    }
    if out.is_empty() {
        return String::new();
    }
    let domain = out[0].domain.trim_start_matches('.').to_string();
    cookies::to_netscape(&out, &domain)
}

/// Count cookie rows in Netscape text — the only cookie-derived value a host
/// may display.
pub fn cookie_count(text: &str) -> usize {
    cookies::count_netscape_cookies(text)
}

/// Normalize pasted cookie data into Netscape text.
///
/// Accepts either a Netscape file's contents or a bare `Cookie:` header
/// (`a=b; c=d`). `domain` fills the Netscape domain column, which is what a
/// downloader matches on.
pub fn normalize_import(input: &str, domain: &str) -> Result<String> {
    let text = input.trim();
    if text.is_empty() {
        return Err(Error::cookie("empty cookie data"));
    }
    if text.lines().any(|l| l.split('\t').count() >= 7) {
        if cookies::count_netscape_cookies(text) > 0 {
            return Ok(format!("{text}\n"));
        }
        return Err(Error::cookie("no cookie rows found in the supplied Netscape file"));
    }
    let mut records = Vec::new();
    for pair in text.split(';') {
        let Some((name, value)) = pair.split_once('=') else { continue };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        records.push(cookies::Cookie {
            name: name.to_string(),
            value: value.trim().to_string(),
            domain: domain.to_string(),
            path: "/".to_string(),
            expires: 0,
            secure: true,
            http_only: false,
        });
    }
    if records.is_empty() {
        return Err(Error::cookie("no `name=value` pairs found in the supplied cookie data"));
    }
    Ok(cookies::to_netscape(&records, domain))
}

/// Read `data` out of a JSON body, defaulting to null.
pub fn data_of(value: &Value) -> Value {
    value.get("data").cloned().unwrap_or(Value::Null)
}

/// Read `code` out of a JSON body, defaulting to -1 (unknown).
pub fn code_of(value: &Value) -> i64 {
    value.get("code").and_then(|v| v.as_i64()).unwrap_or(-1)
}

/// Read `message` out of a JSON body.
pub fn message_of(value: &Value) -> String {
    value.get("message").and_then(|v| v.as_str()).unwrap_or_default().to_string()
}

/// Read a string param out of a params object.
pub fn str_param<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

/// Build a session state object from key/value pairs.
pub fn state_of(pairs: &[(&str, Value)]) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value.clone());
    }
    Value::Object(map)
}
