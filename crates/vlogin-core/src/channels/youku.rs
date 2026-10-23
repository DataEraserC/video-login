//! Youku (优酷) — cookie-based login only.
//!
//! Youku's login runs through Alibaba's shared passport (`passport.youku.com` /
//! `login.taobao.com`), which is a signed, fingerprint-carrying flow: the QR
//! is minted against a per-session device id and the poll is bound to it, and
//! the pieces move whenever the group rotates its anti-bot layer. There is no
//! stable documented web QR endpoint to target, and a half-guessed one fails
//! silently — which is worse than failing loudly.
//!
//! So the two methods that are guaranteed to work are advertised and the QR
//! method is left **reserved**: the host can show it, and asking for it returns
//! an error that says to import cookies instead. That is the honest shape of
//! the capability, and it is cheap to promote later if a stable endpoint turns
//! up.

use std::sync::Arc;

use serde_json::Value;

use super::{require_method, Challenge, CheckOutcome, Provider};
use crate::cookies;
use crate::error::{Error, Result};
use crate::model::{ChannelInfo, MethodInfo, MethodKind};

const DOMAIN: &str = "youku.com";

/// Cookie names Youku sets only for a signed-in session.
const SESSION_COOKIES: &[&str] = &["cna", "ykss", "P_l_id", "P_sck", "aliyun_country"];

/// Youku provider.
pub struct Youku;

impl Youku {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for Youku {
    fn default() -> Self {
        Self
    }
}

impl Provider for Youku {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "youku",
            name: "优酷",
            hosts: vec!["youku.com"],
            cookie_domain: DOMAIN,
            login_url: "https://www.youku.com/",
            methods: vec![
                MethodInfo::live("manual", "手动导入 Cookie", MethodKind::Import),
                MethodInfo::live("browser", "从浏览器读取", MethodKind::Browser),
                MethodInfo::reserved("qr", "扫码登录", MethodKind::Qr),
                MethodInfo::reserved("sms", "短信验证码登录", MethodKind::Credential),
                MethodInfo::reserved("password", "账号密码登录", MethodKind::Credential),
            ],
        }
    }

    fn start(&self, method: &str, params: &Value) -> Result<(Challenge, Value)> {
        require_method(&self.info(), method)?;
        let _ = params;
        Err(Error::channel(
            "youku has no stable headless QR login endpoint (it runs through "
                .to_string()
                + "Alibaba's signed passport); import cookies instead (manual) or "
                + "read them from your browser (browser).",
        ))
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        let cookies = cookies::parse_netscape(cookies_text);
        // `ykss` is the session marker; the others are issued alongside it.
        let logged_in = cookies
            .iter()
            .any(|c| SESSION_COOKIES.iter().any(|name| c.name == *name));
        Ok(CheckOutcome { logged_in, identity: String::new() })
    }
}
