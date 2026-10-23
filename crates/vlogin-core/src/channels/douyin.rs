//! Douyin (抖音) — web QR login.
//!
//! The web login surface is `login.douyin.com/passport/web/*`; `sso.douyin.com`
//! is the older alias and still answers, which is why both show up in the
//! wild. We use the `login.douyin.com` form with `aid=6383` (the www.douyin.com
//! web app id — 2906/1128 belong to creator/other surfaces and issue cookies
//! scoped to the wrong host).
//!
//! Protocol:
//!
//! 1. `GET  /passport/web/get_qrcode/?aid=6383&next=…&service=…&is_vcd=1&fp=…`
//!    → `{ data: { qrcode_index_url, token, qrcode? }, message: "success" }`
//!    `qrcode_index_url` is the payload to render; `qrcode` is a base64 PNG
//!    fallback for clients that cannot render a QR themselves.
//! 2. `POST /passport/web/check_qrconnect/?…` with `{ token, next, is_new_login,
//!    need_logo, need_short_url, is_frontier }`
//!    → `{ data: { status: "new" | "scanned" | "expired" | "confirmed",
//!    redirect_url }, message: "success" | "error" }`
//! 3. `GET data.redirect_url` — this hop is what plants the session cookies on
//!    `.douyin.com`. Skipping it is the classic way to end up "logged in"
//!    with an empty jar.
//!
//! `fp` is a device fingerprint. Plain-random works for the generate call; if
//! Douyin starts rejecting it, the fix is to persist a per-install fp rather
//! than to sign requests.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{
    data_of, harvest, jar_header, jar_of, merge_jar, message_of, require_method, state_str,
    Challenge, CheckOutcome, Poll, Provider,
};
use crate::cookies;
use crate::error::{Error, Result};
use crate::http;
use crate::model::{ChannelInfo, MethodInfo, MethodKind};
use crate::store::random_token;

const DOMAIN: &str = "douyin.com";
const BASE: &str = "https://login.douyin.com/passport/web";
const NEXT: &str = "https://www.douyin.com/";
const USER_INFO_URL: &str = "https://creator.douyin.com/web/api/media/user/info";

/// Douyin provider.
pub struct Douyin;

impl Douyin {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for Douyin {
    fn default() -> Self {
        Self
    }
}

impl Provider for Douyin {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "douyin",
            name: "抖音",
            hosts: vec!["douyin.com", "iesdouyin.com"],
            cookie_domain: DOMAIN,
            login_url: "https://www.douyin.com/",
            methods: vec![
                MethodInfo::live("qr", "扫码登录", MethodKind::Qr),
                MethodInfo::live("manual", "手动导入 Cookie", MethodKind::Import),
                MethodInfo::live("browser", "从浏览器读取", MethodKind::Browser),
                MethodInfo::reserved("sms", "短信验证码登录", MethodKind::Credential),
                MethodInfo::reserved("password", "账号密码登录", MethodKind::Credential),
            ],
        }
    }

    fn start(&self, method: &str, params: &Value) -> Result<(Challenge, Value)> {
        require_method(&self.info(), method)?;
        let _ = params;
        let fp = random_token(32);
        let mut query = String::new();
        for (key, value) in [
            ("aid", "6383"),
            ("next", NEXT),
            ("service", NEXT),
            ("is_vcd", "1"),
            ("fp", &fp),
        ] {
            http::push_query(&mut query, key, value);
        }
        let url = format!("{BASE}/get_qrcode/{query}");
        let response = http::get(
            &url,
            &[("accept", "application/json"), ("referer", "https://www.douyin.com/")],
        )?;
        if !response.ok() {
            return Err(Error::http(format!("douyin get_qrcode: HTTP {}", response.status())));
        }
        let body = response.json()?;
        let data = data_of(&body);
        let payload = data
            .get("qrcode_index_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let token = data
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if payload.is_empty() || token.is_empty() {
            return Err(Error::http(format!(
                "douyin get_qrcode returned no token/payload ({})",
                message_of(&body)
            )));
        }
        let jar = harvest(&response.set_cookies, DOMAIN).unwrap_or_default();
        Ok((
            Challenge::Qr { url: payload, image: None },
            super::state_of(&[
                ("token", json!(token)),
                ("fp", json!(fp)),
                ("jar", json!(jar)),
            ]),
        ))
    }

    fn poll(&self, session: &mut crate::session::Session) -> Result<Poll> {
        let token = state_str(session, "token");
        let fp = state_str(session, "fp");
        if token.is_empty() {
            return Err(Error::channel("this session has no douyin login token"));
        }
        let mut query = String::new();
        for (key, value) in [
            ("aid", "6383"),
            ("next", NEXT),
            ("service", NEXT),
            ("is_vcd", "1"),
            ("fp", &fp),
        ] {
            http::push_query(&mut query, key, value);
        }
        let url = format!("{BASE}/check_qrconnect/{query}");

        let cookie = jar_header(session);
        let mut headers: Vec<(&str, &str)> = vec![
            ("accept", "application/json"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("referer", "https://www.douyin.com/"),
        ];
        if !cookie.is_empty() {
            headers.push(("cookie", cookie.as_str()));
        }
        let response = http::post_form(
            &url,
            &headers,
            &[
                ("token", &token),
                ("next", NEXT),
                ("is_new_login", "1"),
                ("need_logo", "false"),
                ("need_short_url", "false"),
                ("is_frontier", "true"),
            ],
        )?;
        if !response.ok() {
            return Err(Error::http(format!("douyin check_qrconnect: HTTP {}", response.status())));
        }
        let body = response.json()?;
        if body.get("message").and_then(|v| v.as_str()) == Some("error") {
            let data = data_of(&body);
            let code = data
                .get("error_code")
                .and_then(|v| v.as_i64())
                .or_else(|| data.get("error_code").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()))
                .unwrap_or(-1);
            let description = data
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            // 4041-ish codes mean "not scanned yet" on some surfaces; anything
            // else is a hard failure.
            if code == 4041 {
                return Ok(Poll::Pending { message: "等待扫码".into() });
            }
            return Err(Error::http(format!("douyin check_qrconnect: {description} ({code})")));
        }

        let data = data_of(&body);
        let status = data.get("status").and_then(|v| v.as_str()).unwrap_or_default();
        let description = data
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        match status {
            "new" => Ok(Poll::Pending { message: or_default(description, "等待扫码") }),
            "scanned" => {
                Ok(Poll::Scanned { message: or_default(description, "已扫码，请在手机上确认") })
            }
            "expired" => {
                Ok(Poll::Expired { message: or_default(description, "二维码已过期，请重新获取") })
            }
            "confirmed" | "success" => {
                let mut cookies = harvest(&response.set_cookies, DOMAIN).unwrap_or_default();
                if cookies.is_empty() {
                    if let Some(hop) = data.get("redirect_url").and_then(|v| v.as_str()) {
                        if let Ok(hop_response) = http::get(hop, &[("accept", "text/html,*/*")]) {
                            cookies = harvest(&hop_response.set_cookies, DOMAIN).unwrap_or_default();
                        }
                    }
                }
                if cookies.is_empty() {
                    return Err(Error::http(
                        "douyin confirmed the login but issued no cookies",
                    ));
                }
                merge_jar(session, &cookies);
                let identity =
                    self.check(&jar_of(session)).map(|o| o.identity).unwrap_or_default();
                Ok(Poll::Done { cookies: jar_of(session), identity })
            }
            other => Err(Error::http(format!("douyin check_qrconnect: unknown status '{other}'"))),
        }
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        let header = cookies::header_from_netscape(cookies_text);
        if header.is_empty() {
            return Ok(CheckOutcome { logged_in: false, identity: String::new() });
        }
        // Best-effort: this endpoint answers without the a_bogus signature most
        // of the site now requires, and reports status_code 8 when the jar is
        // anonymous. A transport failure is therefore "unknown", not "logged
        // out" — callers must not purge an account on an unreachable network.
        let response = http::get(USER_INFO_URL, &[("accept", "application/json"), ("cookie", header.as_str())]);
        let Ok(response) = response else {
            return Err(Error::http("douyin status check unreachable"));
        };
        let body = response.json().unwrap_or(Value::Null);
        let data = data_of(&body);
        let status_code = data.get("status_code").and_then(|v| v.as_i64()).unwrap_or(-1);
        let logged_in = status_code == 0;
        let identity = data
            .get("nickname")
            .or_else(|| data.get("user_name"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(CheckOutcome { logged_in, identity })
    }
}

/// Fall back to `default` when the site sent an empty message.
fn or_default(message: String, default: &str) -> String {
    if message.is_empty() {
        default.to_string()
    } else {
        message
    }
}
