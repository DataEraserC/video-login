//! Thin HTTP helper used by the providers.
//!
//! Two things providers need that plain `reqwest` does not hand over
//! ergonomically:
//!
//! * the raw `Set-Cookie` response lines, because a login's whole point is to
//!   harvest auth cookies — they are the credential, not incidental metadata;
//! * no automatic redirects, because several sites put the auth cookies on a
//!   redirect hop instead of on the response that reports success.
//!
//! The body is kept as **raw bytes** and decoded on demand. That matters:
//! `ptqrshow` answers with a PNG, and round-tripping binary through a `String`
//! would corrupt it.
//!
//! Secrets boundary: [`Response::set_cookies`] is secret-bearing. It must be
//! funnelled into the account store, never into a log line or an error message
//! — error strings built here carry status codes and truncated bodies only.

use std::collections::HashMap;
use std::time::Duration;

use crate::error::{Error, Result};

/// Browser-ish UA. Some sites refuse a bare reqwest UA outright.
pub const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/126.0.0.0 Safari/537.36 video-login";

/// Default per-request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// A response the providers can inspect.
pub struct Response {
    status: u16,
    bytes: Vec<u8>,
    headers: HashMap<String, String>,
    /// Secret-bearing: raw `Set-Cookie` lines.
    pub set_cookies: Vec<String>,
}

impl Response {
    /// HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// True for 2xx.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Raw body bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Body decoded as UTF-8 (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Parse the body as JSON.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.bytes).map_err(|e| Error::http(format!("bad JSON in response: {e}")))
    }

    /// One response header (case-insensitive lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// `Location` header, when present.
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
}

/// Build a client with redirects disabled.
pub fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(UA)
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::http(format!("cannot build HTTP client: {e}")))
}

/// Run a request described by method/url/headers/body.
fn execute(
    client: &reqwest::blocking::Client,
    method: reqwest::Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<Response> {
    let mut request = client.request(method, url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request.send().map_err(|e| Error::http(format!("request failed: {e}")))?;
    let status = response.status().as_u16();

    let mut header_map = HashMap::new();
    for (name, value) in response.headers().iter() {
        if let Ok(value) = value.to_str() {
            header_map.insert(name.as_str().to_ascii_lowercase(), value.to_string());
        }
    }

    // Walk the raw headers rather than using a cookie store: each login is an
    // isolated jar, and a shared store would leak credentials across accounts.
    let set_cookies = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .collect();

    let bytes = response
        .bytes()
        .map(|b| b.to_vec())
        .map_err(|e| Error::http(format!("cannot read response body: {e}")))?;
    Ok(Response { status, bytes, headers: header_map, set_cookies })
}

/// GET, following no redirects.
pub fn get(url: &str, headers: &[(&str, &str)]) -> Result<Response> {
    execute(&client()?, reqwest::Method::GET, url, headers, None)
}

/// POST with a form-encoded body.
pub fn post_form(url: &str, headers: &[(&str, &str)], form: &[(&str, &str)]) -> Result<Response> {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes();
    let mut all: Vec<(&str, &str)> = vec![("content-type", "application/x-www-form-urlencoded")];
    all.extend_from_slice(headers);
    execute(&client()?, reqwest::Method::POST, url, &all, Some(body))
}

/// POST with a JSON body.
pub fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    payload: &serde_json::Value,
) -> Result<Response> {
    let body = serde_json::to_vec(payload)?;
    let mut all: Vec<(&str, &str)> = vec![("content-type", "application/json")];
    all.extend_from_slice(headers);
    execute(&client()?, reqwest::Method::POST, url, &all, Some(body))
}

pub use crate::util::{push_query, urlencode};
