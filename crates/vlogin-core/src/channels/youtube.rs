//! YouTube — cookie-based login only.
//!
//! ## Why there is no OAuth method here
//!
//! Google's OAuth 2.0 loopback flow for installed apps is well documented and
//! easy to implement, but it is the **wrong credential for this tool**. What it
//! yields is an access/refresh token for the YouTube Data API. It does not give
//! you a `Cookie` header, and a downloader authenticates a `youtube.com` request
//! with cookies (`LOGIN_INFO`, `SID`, `HSID`, `SSID`, `APISID`, `SAPISID`, …) —
//! not with a bearer token. Shipping an OAuth button would produce accounts
//! that report "logged in" while every download stayed anonymous.
//!
//! So the credential model here matches what actually authorizes a download:
//!
//! * `manual`  — paste a Netscape cookie file or a `Cookie:` header.
//! * `browser` — pull the cookies straight out of a local Chrome/Chromium
//!   profile over CDP (see `crate::browser`). This is the same trick
//!   `yt-dlp --cookies-from-browser` uses, and it is the one that survives
//!   YouTube rotating its session cookies.
//!
//! `oauth` is advertised as reserved with an error that says exactly this, so a
//! host can show the option and explain it instead of silently failing.
//!
//! Status check: the YouTube Data API `channels?mine=true` endpoint needs OAuth,
//! which we do not hold, so `check()` answers from the cookie jar itself — the
//! presence of a session cookie is the only claim we can honestly make.

use std::sync::Arc;

use serde_json::Value;

use super::{require_method, Challenge, CheckOutcome, Provider};
use crate::cookies;
use crate::error::{Error, Result};
use crate::model::{ChannelInfo, MethodInfo, MethodKind};

const DOMAIN: &str = "youtube.com";

/// Cookie names YouTube sets only for a signed-in session. Presence of any of
/// these is the strongest login signal available without OAuth.
const SESSION_COOKIES: &[&str] = &["LOGIN_INFO", "SID", "APISID", "SAPISID", "HSID", "SSID"];

/// YouTube provider.
pub struct YouTube;

impl YouTube {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for YouTube {
    fn default() -> Self {
        Self
    }
}

impl Provider for YouTube {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "youtube",
            name: "YouTube",
            hosts: vec!["youtube.com", "youtu.be"],
            cookie_domain: DOMAIN,
            login_url: "https://www.youtube.com/",
            methods: vec![
                MethodInfo::live("manual", "手动导入 Cookie", MethodKind::Import),
                MethodInfo::live("browser", "从浏览器读取", MethodKind::Browser),
                MethodInfo::reserved("qr", "扫码登录", MethodKind::Qr),
                MethodInfo::reserved("oauth", "Google 账号授权", MethodKind::Credential),
            ],
        }
    }

    fn start(&self, method: &str, params: &Value) -> Result<(Challenge, Value)> {
        require_method(&self.info(), method)?;
        let _ = params;
        Err(Error::channel(
            "youtube: an OAuth login would only yield API tokens, not the cookies a "
                .to_string()
                + "downloader sends; import cookies instead (manual) or read them from "
                + "your browser (browser).",
        ))
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        let cookies = cookies::parse_netscape(cookies_text);
        let logged_in = cookies
            .iter()
            .any(|c| SESSION_COOKIES.iter().any(|name| c.name == *name));
        // No identity is derivable from cookies alone — that needs the API.
        Ok(CheckOutcome { logged_in, identity: String::new() })
    }
}
