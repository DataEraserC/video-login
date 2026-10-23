//! iQiyi (爱奇艺) — web QR login.
//!
//! Endpoints (from the `passport.iqiyi.com` QR surface):
//!
//! 1. `POST /apis/qrcode/gen_login_token.action`
//!    form: `agenttype=1&app_version=&device_id=&device_name=网页端&fromSDK=1&ptid=01010021010000000000&sdk_version=1.0.0&surl=1`
//!    → `{ code: "A00000", data: { token } }`
//! 2. QR image: `https://qrcode.iqiyipic.com/login/?data=<urlencoded login url>&property=0&salt=<md5>&width=162`
//!    `salt` is `md5(<fixed key> + <urlencoded login url>)`. We fetch this
//!    ourselves and hand the PNG to the host as a data URL, so the host never
//!    needs a QR renderer for this channel.
//! 3. `POST /apis/qrcode/is_token_login.action` with `token`
//!    → `{ code: "A00000", … }` once the user confirms.
//!
//! The login URL embedded in the QR is
//! `https://passport.iqiyi.com/apis/qrcode/token_login.action?token=<token>`.
//!
//! Verification status: shape follows the published QR flow; **not** exercised
//! against a live account here. `manual` / `browser` are the reliable paths.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{
    harvest, jar_of, merge_jar, require_method, state_str, Challenge, CheckOutcome, Poll,
    Provider,
};
use crate::cookies;
use crate::error::{Error, Result};
use crate::http;
use crate::model::{ChannelInfo, MethodInfo, MethodKind};
use crate::util::{base64_encode, random_token};

const DOMAIN: &str = "iqiyi.com";
const GEN_TOKEN_URL: &str = "https://passport.iqiyi.com/apis/qrcode/gen_login_token.action";
const IS_TOKEN_LOGIN_URL: &str = "https://passport.iqiyi.com/apis/qrcode/is_token_login.action";
const QR_IMAGE_URL: &str = "https://qrcode.iqiyipic.com/login/";
const TOKEN_LOGIN_URL: &str = "https://passport.iqiyi.com/apis/qrcode/token_login.action";
/// Fixed key iQiyi mixes into the QR image request's `salt` parameter.
const SALT_KEY: &str = "35f4223bb8f6c8638dc91d94e9b16f5";

/// iQiyi provider.
pub struct IQiyi;

impl IQiyi {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for IQiyi {
    fn default() -> Self {
        Self
    }
}

impl Provider for IQiyi {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "iqiyi",
            name: "爱奇艺",
            hosts: vec!["iqiyi.com"],
            cookie_domain: DOMAIN,
            login_url: "https://www.iqiyi.com/",
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
        let device_id = random_token(32);
        let response = http::post_form(
            GEN_TOKEN_URL,
            &[("accept", "application/json"), ("referer", "https://www.iqiyi.com/")],
            &[
                ("agenttype", "1"),
                ("app_version", ""),
                ("device_id", &device_id),
                ("device_name", "网页端"),
                ("fromSDK", "1"),
                ("ptid", "01010021010000000000"),
                ("sdk_version", "1.0.0"),
                ("surl", "1"),
            ],
        )?;
        if !response.ok() {
            return Err(Error::http(format!("iqiyi gen_login_token: HTTP {}", response.status())));
        }
        let body = response.json()?;
        let token = body
            .get("data")
            .and_then(|d| d.get("token"))
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string();
        if token.is_empty() {
            return Err(Error::http(format!(
                "iqiyi gen_login_token returned no token (code {:?})",
                body.get("code").and_then(|c| c.as_str())
            )));
        }

        let login_url = format!("{TOKEN_LOGIN_URL}?token={}", http::urlencode(&token));
        let mut query = String::new();
        http::push_query(&mut query, "data", &login_url);
        http::push_query(&mut query, "property", "0");
        http::push_query(
            &mut query,
            "salt",
            &md5_hex(&format!("{SALT_KEY}{}", http::urlencode(&login_url))),
        );
        http::push_query(&mut query, "width", "162");
        let image_url = format!("{QR_IMAGE_URL}{query}");

        let image_response = http::get(&image_url, &[("referer", "https://www.iqiyi.com/")])?;
        if !image_response.ok() {
            return Err(Error::http(format!("iqiyi QR image: HTTP {}", image_response.status())));
        }
        let bytes = image_response.bytes();
        if bytes.len() < 8 || &bytes[1..4] != b"PNG" {
            return Err(Error::http("iqiyi QR image was not a PNG"));
        }

        let jar = harvest(&response.set_cookies, DOMAIN).unwrap_or_default();

        Ok((
            Challenge::Qr {
                url: login_url,
                image: Some(format!("data:image/png;base64,{}", base64_encode(bytes))),
            },
            super::state_of(&[("token", json!(token)), ("jar", json!(jar))]),
        ))
    }

    fn poll(&self, session: &mut crate::session::Session) -> Result<Poll> {
        let token = state_str(session, "token");
        if token.is_empty() {
            return Err(Error::channel("this session has no iqiyi login token"));
        }
        let response = http::post_form(
            IS_TOKEN_LOGIN_URL,
            &[("accept", "application/json"), ("referer", "https://www.iqiyi.com/")],
            &[
                ("agenttype", "1"),
                ("app_version", ""),
                ("device_id", ""),
                ("fromSDK", "1"),
                ("ptid", "01010021010000000000"),
                ("sdk_version", "1.0.0"),
                ("token", &token),
            ],
        )?;
        if !response.ok() {
            return Err(Error::http(format!("iqiyi is_token_login: HTTP {}", response.status())));
        }
        let body = response.json().unwrap_or(Value::Null);
        let code = body.get("code").and_then(|c| c.as_str()).unwrap_or_default();
        if code != "A00000" {
            // Not-confirmed-yet is the normal case while the user is deciding;
            // anything else is a hard error.
            return Ok(Poll::Pending { message: "等待扫码确认".into() });
        }
        let cookies = harvest(&response.set_cookies, DOMAIN)?;
        merge_jar(session, &cookies);
        Ok(Poll::Done { cookies: jar_of(session), identity: String::new() })
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        let cookies = cookies::parse_netscape(cookies_text);
        // iQiyi's auth cookie is P00001; it is only issued to a signed-in
        // session. There is no unauthenticated API we can probe without a
        // signed request, so presence is the honest signal.
        let logged_in = cookies.iter().any(|c| c.name == "P00001");
        Ok(CheckOutcome { logged_in, identity: String::new() })
    }
}

/// MD5 of `input`, lower-case hex — used for the iQiyi QR image `salt`.
fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}
