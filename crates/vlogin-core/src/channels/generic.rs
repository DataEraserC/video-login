//! Generic channel — cookie import for any host, no login protocol.
//!
//! This is the escape hatch. The registry's URL routing falls back to it, so a
//! video URL the tool has never heard of is still usable: the agent can import
//! cookies for that host and a downloader will send them.
//!
//! There is deliberately no QR or credential method here. "Log in" to an
//! arbitrary host means either pasting cookies or reading them from a browser —
//! there is no protocol to speak.
//!
//! The generic channel keeps **one** account per host, keyed by the host, so
//! cookies for `example.com` never leak into a request for `other.com`.

use std::sync::Arc;

use serde_json::Value;

use super::{require_method, Challenge, CheckOutcome, Provider};
use crate::cookies;
use crate::error::Result;
use crate::model::{ChannelInfo, MethodInfo, MethodKind};

/// Generic provider. `cookie_domain` is filled in per host at call time, so the
/// advertised value is only a placeholder.
pub struct Generic;

impl Generic {
    /// Construct a boxed provider for the registry.
    pub fn new() -> Arc<dyn Provider> {
        Arc::new(Self)
    }
}

impl Default for Generic {
    fn default() -> Self {
        Self
    }
}

impl Provider for Generic {
    fn info(&self) -> ChannelInfo {
        ChannelInfo {
            id: "generic",
            name: "其他站点",
            hosts: vec![],
            cookie_domain: "",
            login_url: "",
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
        Err(super::unsupported(&self.info(), method))
    }

    fn check(&self, cookies_text: &str) -> Result<CheckOutcome> {
        // With no site API to ask, the only defensible answer is "there are
        // cookies here". Callers must not treat this as proof of a live
        // session.
        let logged_in = cookies::count_netscape_cookies(cookies_text) > 0;
        Ok(CheckOutcome { logged_in, identity: String::new() })
    }
}
