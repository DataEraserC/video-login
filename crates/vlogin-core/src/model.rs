//! Data model shared by the core, the ABI and the CLI.
//!
//! Two orthogonal dimensions matter here, and getting them apart is the whole
//! point of the redesign:
//!
//! * **channel** — which video site (bilibili, douyin, youtube, …). Each
//!   channel owns its hosts, its cookie domain and the set of login methods it
//!   implements.
//! * **method** — how a credential is obtained *within* a channel (`qr`,
//!   `manual`, `sms`, `password`, `browser`). The registry reserves the full
//!   method enum globally so a caller always gets a structured "not
//!   implemented by this channel" answer instead of a missing capability.
//!
//! On top of that sits the **account pool**: one channel can hold many
//! accounts, each captured through any method, each with its own status. An
//! active account is pinned per channel and every other account is a
//! ready-made fallback when the active one is rejected at download time.

use serde::{Deserialize, Serialize};

/// Global method dimension. Reserved values are advertised by every channel so
/// a host can render a complete picker and get a typed refusal when it asks a
/// channel for something it does not implement.
pub const ALL_METHODS: &[&str] = &["qr", "manual", "sms", "password", "browser", "oauth"];

/// Which login surface a method drives, so a host knows what to render without
/// hard-coding method names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    /// Scan a QR code, then poll (`qr`).
    Qr,
    /// Paste a Netscape cookie file / Cookie header (`manual`).
    Import,
    /// Multi-step credential flow: send → verify (`sms`, `password`).
    Credential,
    /// Drive a real browser and pull cookies out of it (`browser`).
    Browser,
}

/// One login method as advertised by a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    /// Machine id, one of [`ALL_METHODS`].
    pub id: &'static str,
    /// Human label for pickers, e.g. "扫码登录".
    pub label: &'static str,
    /// What the host has to render.
    pub kind: MethodKind,
    /// True when the channel actually implements it.
    pub implemented: bool,
    /// Input fields a `Credential` method asks for, in order.
    /// `secret: true` means never echo the value back.
    pub fields: Vec<FieldSpec>,
}

/// One input field of a [`MethodKind::Credential`] method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub label: String,
    pub secret: bool,
}

impl MethodInfo {
    /// An implemented method.
    pub fn live(id: &'static str, label: &'static str, kind: MethodKind) -> Self {
        Self { id, label, kind, implemented: true, fields: Vec::new() }
    }

    /// An implemented credential method with input fields.
    pub fn credential(id: &'static str, label: &'static str, fields: Vec<FieldSpec>) -> Self {
        Self { id, label, kind: MethodKind::Credential, implemented: true, fields }
    }

    /// A reserved method: advertised but not implemented by this channel.
    pub fn reserved(id: &'static str, label: &'static str, kind: MethodKind) -> Self {
        Self { id, label, kind, implemented: false, fields: Vec::new() }
    }
}

/// A channel as advertised to hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// Registry key; also the account-file name.
    pub id: &'static str,
    /// Display name shown in the picker — the label that was missing before.
    pub name: &'static str,
    /// Host suffixes this channel owns (exact or dot-suffix match).
    pub hosts: Vec<&'static str>,
    /// Fallback Netscape domain for cookies arriving without `Domain=`.
    pub cookie_domain: &'static str,
    /// The site's login page, for methods that cannot run headless.
    pub login_url: &'static str,
    pub methods: Vec<MethodInfo>,
}

/// What a `start` call hands back to the host to render.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Challenge {
    /// Render a QR code and poll until it resolves.
    ///
    /// `image` is set when the site hands back a pre-rendered PNG instead of a
    /// payload (Tencent/QQ's `ptqrshow` does exactly that) — it is a data URL,
    /// so a host renders it directly and falls back to encoding `url` when it
    /// is absent. `url` is the canonical identifier of the challenge either
    /// way, and is what gets logged; it is **not** a secret.
    Qr { url: String, image: Option<String> },
    /// Ask for these fields, then `submit` them.
    Fields { prompt: String, fields: Vec<FieldSpec> },
    /// Open this URL in a browser; the caller polls. Used by OAuth loopback
    /// and by the browser-cookie method.
    Browse { url: String, prompt: String },
    /// The method needs no interaction (never emitted today; kept so hosts can
    /// exhaustively match).
    None,
}

/// Outcome of one `poll` / `submit` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Poll {
    /// Nothing happened yet — keep polling.
    Pending { message: String },
    /// The user scanned but has not confirmed.
    Scanned { message: String },
    /// The challenge went stale; start over.
    Expired { message: String },
    /// Another piece of input is needed — an SMS code, a second factor. The
    /// host re-renders the fields and calls `submit` again.
    NeedInput { prompt: String, fields: Vec<FieldSpec> },
    /// Credentials are in hand.
    Done { cookies: String, identity: String },
}

/// Health of one stored account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    /// Never probed since import.
    Unknown,
    /// The channel's status endpoint says logged in.
    Active,
    /// Probed and rejected (cookie expired / logged out upstream).
    Expired,
    /// The probe itself failed (network, upstream error).
    Unreachable,
}

/// One stored account in a channel's pool.
///
/// Secret-bearing: `cookies` is Netscape text. Instances must never be logged,
/// serialized into a tool result, or sent to a UI — see `AccountView` for the
/// safe projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Stable random id.
    pub id: String,
    /// User-facing label; defaults to the identity reported by the site.
    pub label: String,
    /// Method that produced this account (`qr`, `manual`, …).
    pub method: String,
    /// Milliseconds since the epoch.
    pub created_at: i64,
    pub updated_at: i64,
    /// Last successful probe, 0 when never probed.
    pub last_checked_at: i64,
    pub status: AccountStatus,
    /// Identity reported by the site at capture time (nickname / channel name).
    pub identity: String,
    /// Netscape cookie text. SECRET.
    pub cookies: String,
}

impl Account {
    /// Project to the safe shape hosts may render.
    pub fn view(&self) -> AccountView {
        AccountView {
            id: self.id.clone(),
            label: self.label.clone(),
            method: self.method.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_checked_at: self.last_checked_at,
            status: self.status,
            identity: self.identity.clone(),
            cookie_count: crate::cookies::count_netscape_cookies(&self.cookies),
        }
    }
}

/// Secret-free projection of an [`Account`]. This is what crosses the ABI into
/// a tool result or a web response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountView {
    pub id: String,
    pub label: String,
    pub method: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_checked_at: i64,
    pub status: AccountStatus,
    pub identity: String,
    /// Enough to show "this account has credentials" without leaking them.
    pub cookie_count: usize,
}

/// A channel's persisted pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFile {
    /// Bumped when the on-disk shape changes; drives legacy migration.
    pub version: u32,
    /// Id of the pinned account, if any.
    pub active: Option<String>,
    pub accounts: Vec<Account>,
}

impl Default for AccountFile {
    fn default() -> Self {
        Self { version: crate::store::ACCOUNT_FILE_VERSION, active: None, accounts: Vec::new() }
    }
}
