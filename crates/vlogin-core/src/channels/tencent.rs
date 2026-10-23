//! Tencent Video (腾讯视频) — QR login via the shared QQ ptlogin2 surface.
//!
//! v.qq.com does not have its own login protocol; it borrows QQ's. The flow is
//! the long-standing `ptlogin2` QR dance, which is unusual in two ways and
//! worth knowing before touching it:
//!
//! * `ptqrshow` returns a **PNG image**, not a text payload — there is no QR
//!   content to render, so the challenge carries the image as a data URL.
//! * the poll response is **not JSON**. It is a JavaScript fragment,
//!   `ptuiCB('66','0','','0','二维码未失效.(4010186919)', '')`, whose first
//!   argument is the state code. We parse it with a tiny scanner rather than a
//!   regex crate.
//!
//! State codes: `0` success (argument 2 is the URL to follow), `65` expired,
//! `66` waiting to be scanned, `67` scanned, awaiting confirmation.
//!
//! The confirmation hop matters: it is what plants `vqq_vuserid`,
//! `vqq_vusession` and friends on `.v.qq.com`. Stopping at the poll response
//! yields an empty jar.
//!
//! Verification status: the request shape follows the documented ptlogin2
//! protocol; it has **not** been exercised against a live QQ account from this
//! environment, so treat failures here as expected and fall back to `manual`.

use std::sync::Arc;

use serde_json::{json, Value};

use super::{
    harvest, jar_header, jar_of, merge_jar, require_method, state_str, Challenge, CheckOutcome,
    Poll, Provider,
};
use crate::cookies;
use crate::error::{Error, Result};
use crate::http;
use crate::model::{ChannelInfo, MethodInfo, MethodKind};
use crate::util::{base64_encode, now_ms};

const DOMAIN: &str = "v.qq.com";
/// ptlogin2 app id used by the v.qq.com web login.
const APP_ID: &str = "716027609";
/// `daid` for v.qq.com.
const DA_ID: &str = "383";
const QR_SHOW_URL: &str = "https://ssl.ptlogin2.qq.com/ptqrshow";
const QR_LOGIN_URL: &str = "https://ssl.ptlogin2.qq.com/ptqrlogin";
const CHECK_URL: &str = "https://access.video.qq.com/user/auth_login";

/// Tencent Video provider.
pub struct Tencent;

impl Tencent {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for Tencent {
    fn default() -> Self {
        Self
    }
}

impl Provider for Tencent {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "tencent",
            name: "腾讯视频",
            hosts: vec!["v.qq.com", "video.qq.com"],
            cookie_domain: DOMAIN,
            login_url: "https://v.qq.com/",
            methods: vec![
                MethodInfo::live("qr", "扫码登录（QQ）", MethodKind::Qr),
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
        let mut query = String::new();
        for (key, value) in [
            ("appid", APP_ID),
            ("e", "2"),
            ("l", "M"),
            ("s", "3"),
            ("d", "72"),
            ("v", "4"),
            ("t", &format!("0.{}", now_ms() % 1000000)),
            ("daid", DA_ID),
            ("pt_3rd_aid", "0"),
        ] {
            http::push_query(&mut query, key, value);
        }
        let url = format!("{QR_SHOW_URL}{query}");
        let response = http::get(&url, &[("referer", "https://v.qq.com/")])?;
        if !response.ok() {
            return Err(Error::http(format!("tencent ptqrshow: HTTP {}", response.status())));
        }
        let bytes = response.bytes();
        if bytes.len() < 8 || &bytes[1..4] != b"PNG" {
            return Err(Error::http(
                "tencent ptqrshow did not return a PNG image",
            ));
        }

        // qrsig is the whole basis of the poll token, so it has to be kept.
        let mut jar = harvest(&response.set_cookies, DOMAIN)?;
        let Some(qrsig) = response
            .set_cookies
            .iter()
            .find_map(|line| {
                let (pair, _) = line.split_once(';')?;
                let (name, value) = pair.split_once('=')?;
                (name.trim() == "qrsig").then(|| value.trim().to_string())
            })
        else {
            return Err(Error::http("tencent ptqrshow issued no qrsig cookie"));
        };
        let _ = &mut jar;

        let token = hash33(&qrsig);
        Ok((
            Challenge::Qr {
                url: url.clone(),
                image: Some(format!("data:image/png;base64,{}", base64_encode(&bytes))),
            },
            super::state_of(&[
                ("qrsig", json!(qrsig)),
                ("token", json!(token)),
                ("jar", json!(jar)),
                ("appid", json!(APP_ID)),
            ]),
        ))
    }

    fn poll(&self, session: &mut crate::session::Session) -> Result<Poll> {
        let qrsig = state_str(session, "qrsig");
        let token = state_str(session, "token");
        if qrsig.is_empty() || token.is_empty() {
            return Err(Error::channel("this session has no QQ qr login token"));
        }
        let mut query = String::new();
        let timestamp = now_ms().to_string();
        for (key, value) in [
            ("u1", "https://v.qq.com/"),
            ("ptqrtoken", &token),
            ("ptredirect", "0"),
            ("h", "1"),
            ("t", "1"),
            ("g", "1"),
            ("from_ui", "1"),
            ("ptlang", "2052"),
            ("action", &format!("0-0-{timestamp}")),
            ("js_ver", "10222"),
            ("js_type", "1"),
            ("login_sig", ""),
            ("pt_uistyle", "40"),
            ("aid", APP_ID),
            ("daid", DA_ID),
            ("pt_3rd_aid", "0"),
            ("", ""),
        ] {
            if key.is_empty() {
                query.push('&');
            } else {
                http::push_query(&mut query, key, value);
            }
        }
        let url = format!("{QR_LOGIN_URL}{query}");

        let cookie = format!("qrsig={qrsig}");
        let headers = [
            ("referer", "https://xui.ptlogin2.qq.com/"),
            ("cookie", cookie.as_str()),
        ];
        let response = http::get(&url, &headers)?;
        if !response.ok() {
            return Err(Error::http(format!("tencent ptqrlogin: HTTP {}", response.status())));
        }
        let args = parse_ptui_cb(&response.text());
        let state = args.first().map(|s| s.as_str()).unwrap_or_default();
        let detail = args.get(4).cloned().unwrap_or_default();

        match state {
            "0" => {
                let mut cookies = harvest(&response.set_cookies, DOMAIN).unwrap_or_default();
                let redirect = args.get(1).cloned().unwrap_or_default();
                if cookies.is_empty() && !redirect.is_empty() {
                    let hop_cookie = jar_header(session);
                    let hop_headers = if hop_cookie.is_empty() {
                        vec![("referer", "https://v.qq.com/")]
                    } else {
                        vec![("referer", "https://v.qq.com/"), ("cookie", hop_cookie.as_str())]
                    };
                    if let Ok(hop_response) = http::get(&redirect, &hop_headers) {
                        cookies = harvest(&hop_response.set_cookies, DOMAIN).unwrap_or_default();
                    }
                }
                if cookies.is_empty() {
                    return Err(Error::http(
                        "tencent confirmed the login but issued no cookies",
                    ));
                }
                merge_jar(session, &cookies);
                Ok(Poll::Done {
                    cookies: jar_of(session),
                    identity: state_str(session, "identity"),
                })
            }
            "65" => Ok(Poll::Expired { message: or_default(detail, "二维码已失效，请重新获取") }),
            "66" => Ok(Poll::Pending { message: or_default(detail, "等待扫码") }),
            "67" => Ok(Poll::Scanned { message: or_default(detail, "已扫码，请在 QQ 上确认") }),
            other => Err(Error::http(format!("tencent ptqrlogin: unexpected state '{other}'"))),
        }
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        let header = cookies::header_from_netscape(cookies_text);
        if header.is_empty() {
            return Ok(CheckOutcome { logged_in: false, identity: String::new() });
        }
        let response = http::get(
            CHECK_URL,
            &[("accept", "application/json"), ("cookie", header.as_str())],
        )?;
        let body = response.json().unwrap_or(Value::Null);
        // v.qq.com reports an unauthenticated jar as `{"ret": -1, ...}` or with
        // an empty `vuserid`; anything else with data is treated as signed in.
        let data = data_of(&body);
        let ret = body.get("ret").and_then(|v| v.as_i64()).unwrap_or(-1);
        let vuserid = data
            .get("vuserid")
            .or_else(|| data.get("nick"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
        let logged_in = ret == 0 || vuserid.is_some();
        Ok(CheckOutcome { logged_in, identity: vuserid.unwrap_or_default() })
    }
}

/// `data` accessor kept local to avoid widening the shared helper's scope.
fn data_of(value: &Value) -> Value {
    value.get("data").cloned().unwrap_or(Value::Null)
}

/// QQ's classic string hash, used to derive `ptqrtoken` from the `qrsig`
/// cookie. Arithmetic must wrap the way the reference implementation's does.
fn hash33(input: &str) -> i64 {
    let mut acc: i64 = 0;
    for byte in input.bytes() {
        acc = acc.wrapping_mul(33).wrapping_add(i64::from(byte));
    }
    acc & 0x7fff_ffff
}

/// Pull the arguments out of a `ptuiCB('66','0',…)` fragment.
///
/// Handles single-quoted strings only, which is all ptlogin2 emits. Escaped
/// quotes are not part of the format, so they are not handled.
fn parse_ptui_cb(body: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current: Option<String> = None;
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => match current.take() {
                Some(value) => args.push(value),
                None => current = Some(String::new()),
            },
            '\\' => {
                if let Some(value) = current.as_mut() {
                    if let Some(next) = chars.next() {
                        value.push(next);
                    }
                }
            }
            other => {
                if let Some(value) = current.as_mut() {
                    value.push(other);
                }
            }
        }
    }
    args
}

/// Fall back to `default` when the site sent an empty message.
fn or_default(message: String, default: &str) -> String {
    if message.is_empty() {
        default.to_string()
    } else {
        message
    }
}
