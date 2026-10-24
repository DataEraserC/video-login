//! Per-channel account pool storage.
//!
//! Layout under the state root (see [`Store::root`]):
//!
//! ```text
//! accounts/<channel>.json      the pool: { version, active, accounts: [...] }
//! accounts/<channel>.jar.txt   the pinned account, materialized for a downloader
//! cookies/<channel>.json       LEGACY: bare jar array from dsh-video-fetch ≤0.2
//! cookies/<channel>.jar.txt    LEGACY: materialized jar
//! sessions/<id>.json           pending login challenges (see session.rs)
//! ```
//!
//! The legacy `cookies/` files are **read but never written**. On the first
//! load of a channel with no `accounts/` file they are imported and left
//! untouched on disk, so an older plugin can still read them after an upgrade
//! in either direction.
//!
//! Secrets boundary: every file here is created 0600 inside a 0700 directory.
//! Functions in this module return [`AccountView`](crate::model::AccountView)
//! or cookie *counts*; only [`Store::cookies_for`] and
//! [`Store::materialize`] return secret text, and both are internal to
//! download/export paths that must not log it.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cookies;
use crate::error::{Error, Result};
use crate::model::{Account, AccountFile, AccountStatus, AccountView};

pub use crate::util::{new_id, now_ms, random_token};

/// Pick the first non-empty candidate, for defaulting an account label.
fn first_nonempty(candidates: &[&str]) -> String {
    candidates.iter().find(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()).unwrap_or_default()
}

/// Bump when the on-disk pool shape changes incompatibly.
pub const ACCOUNT_FILE_VERSION: u32 = 2;

/// How many accounts one channel keeps before the oldest is dropped.
pub const MAX_ACCOUNTS: usize = 10;

/// Resolve the state root.
///
/// Precedence: `$VLOGIN_HOME` → `$XDG_DATA_HOME/video-login` →
/// `~/.local/share/video-login`.
///
/// This crate is harness-independent and has to stay that way, so it knows
/// nothing about `DSH_HOME`. A harness that keeps its state somewhere else
/// (dsh keeps it in `$DSH_HOME/video-fetch`) exports that into `VLOGIN_HOME`
/// before the first call; the older preference for `$DSH_HOME` is what made
/// the "no harness assumed" claim conditional on an environment variable.
pub fn default_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("VLOGIN_HOME") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")));
    match base {
        Some(base) => base.join("video-login"),
        None => PathBuf::from(".video-login"),
    }
}

/// On-disk account pool, one JSON file per channel.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (but do not create) a store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Open the store at the default location.
    pub fn open_default() -> Self {
        Self::new(default_root())
    }

    /// State root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn accounts_dir(&self) -> PathBuf {
        self.root.join("accounts")
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    /// Directory holding pending login sessions. Created on demand.
    pub fn session_dir(&self) -> PathBuf {
        self.sessions_dir()
    }

    fn pool_path(&self, channel: &str) -> PathBuf {
        self.accounts_dir().join(format!("{channel}.json"))
    }

    /// Absolute path of the materialized Netscape file for a channel.
    pub fn jar_path(&self, channel: &str) -> PathBuf {
        self.accounts_dir().join(format!("{channel}.jar.txt"))
    }

    fn legacy_pool_path(&self, channel: &str) -> PathBuf {
        self.root.join("cookies").join(format!("{channel}.json"))
    }

    /// Ensure `accounts/` and `sessions/` exist with 0700.
    fn ensure_dirs(&self) -> Result<()> {
        for dir in [self.accounts_dir(), self.sessions_dir()] {
            fs::create_dir_all(&dir)
                .map_err(|e| Error::other(format!("cannot create {}: {e}", dir.display())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    /// Load a channel's pool, migrating the legacy jar array on first read.
    ///
    /// The legacy file is left in place. Migration is not written back unless
    /// the pool is later mutated, so an untouched install keeps working with an
    /// older plugin.
    pub fn load(&self, channel: &str) -> Result<AccountFile> {
        let path = self.pool_path(channel);
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(file) = serde_json::from_str::<AccountFile>(&text) {
                if file.version == ACCOUNT_FILE_VERSION {
                    return Ok(file);
                }
                // A future/older version we do not understand: fall through to
                // a fresh empty pool rather than corrupting it on write.
                return Err(Error::other(format!(
                    "{}: unsupported account file version {} (expected {})",
                    path.display(),
                    file.version,
                    ACCOUNT_FILE_VERSION
                )));
            }
        }
        Ok(self.migrate_legacy(channel))
    }

    /// Read the legacy `cookies/<channel>.json` jar array as a pool.
    fn migrate_legacy(&self, channel: &str) -> AccountFile {
        let legacy = self.legacy_pool_path(channel);
        let jars: Vec<LegacyJar> = fs::read_to_string(&legacy)
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<LegacyJar>>(&text).ok())
            .unwrap_or_default();

        let mut accounts = Vec::new();
        for jar in jars {
            if cookies::count_netscape_cookies(&jar.data) == 0 {
                continue;
            }
            accounts.push(Account {
                id: new_id(),
                label: String::new(),
                method: if jar.source.is_empty() { "manual".into() } else { jar.source },
                created_at: jar.created_at,
                updated_at: jar.created_at,
                last_checked_at: 0,
                status: AccountStatus::Unknown,
                identity: String::new(),
                cookies: jar.data,
            });
        }
        if accounts.is_empty() {
            return AccountFile::default();
        }
        // Newest first is the legacy convention; the first entry was the one
        // materialized for yt-dlp, so it stays pinned.
        let active = accounts.first().map(|a| a.id.clone());
        AccountFile { version: ACCOUNT_FILE_VERSION, active, accounts }
    }

    /// Persist a channel's pool (0600).
    pub fn save(&self, channel: &str, file: &AccountFile) -> Result<()> {
        self.ensure_dirs()?;
        let path = self.pool_path(channel);
        let text = serde_json::to_string_pretty(file)?;
        fs::write(&path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Add or refresh an account.
    ///
    /// Cookies are compared by value: re-importing an identical jar refreshes
    /// the existing record instead of adding a duplicate.
    pub fn upsert(
        &self,
        channel: &str,
        method: &str,
        cookies_text: &str,
        identity: &str,
        label: &str,
    ) -> Result<AccountView> {
        if cookies::count_netscape_cookies(cookies_text) == 0 {
            return Err(Error::cookie("no cookie rows in the supplied cookie data"));
        }
        let mut file = self.load(channel)?;
        let now = now_ms();
        if let Some(existing) = file.accounts.iter_mut().find(|a| a.cookies == cookies_text) {
            existing.updated_at = now;
            existing.last_checked_at = now;
            existing.status = AccountStatus::Active;
            if !identity.is_empty() {
                existing.identity = identity.to_string();
            }
            if existing.label.is_empty() {
                existing.label = first_nonempty(&[label, identity, method]);
            }
            let view = existing.view();
            self.save(channel, &file)?;
            return Ok(view);
        }

        let account = Account {
            id: new_id(),
            label: first_nonempty(&[label, identity, method]),
            method: method.to_string(),
            created_at: now,
            updated_at: now,
            last_checked_at: now,
            status: AccountStatus::Active,
            identity: identity.to_string(),
            cookies: cookies_text.to_string(),
        };
        let view = account.view();
        file.accounts.insert(0, account);
        while file.accounts.len() > MAX_ACCOUNTS {
            file.accounts.pop();
        }
        if file.active.is_none() {
            file.active = file.accounts.first().map(|a| a.id.clone());
        }
        self.save(channel, &file)?;
        Ok(view)
    }

    /// List a channel's accounts as safe views, pinned account first.
    pub fn list(&self, channel: &str) -> Result<Vec<AccountView>> {
        let file = self.load(channel)?;
        let active = file.active.clone();
        let mut views: Vec<AccountView> = file.accounts.iter().map(|a| a.view()).collect();
        views.sort_by_key(|v| if active.as_deref() == Some(v.id.as_str()) { 0 } else { 1 });
        Ok(views)
    }

    /// Find one account by id.
    pub fn get(&self, channel: &str, id: &str) -> Result<Account> {
        self.load(channel)?
            .accounts
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| Error::channel(format!("no account {id} for channel {channel}")))
    }

    /// The pinned account, falling back to the first in the pool.
    pub fn active(&self, channel: &str) -> Result<Account> {
        let file = self.load(channel)?;
        let id = file.active.clone().or_else(|| file.accounts.first().map(|a| a.id.clone()));
        let id = id.ok_or_else(|| Error::channel(format!("no accounts for channel {channel}")))?;
        file.accounts.into_iter().find(|a| a.id == id).ok_or_else(|| {
            Error::channel(format!("pinned account {id} vanished from {channel}"))
        })
    }

    /// Pin an account as the channel's active credential.
    pub fn pin(&self, channel: &str, id: &str) -> Result<AccountView> {
        let mut file = self.load(channel)?;
        if !file.accounts.iter().any(|a| a.id == id) {
            return Err(Error::channel(format!("no account {id} for channel {channel}")));
        }
        file.active = Some(id.to_string());
        self.save(channel, &file)?;
        self.get(channel, id).map(|a| a.view())
    }

    /// Drop one account; returns true when something was removed.
    pub fn remove(&self, channel: &str, id: &str) -> Result<bool> {
        let mut file = self.load(channel)?;
        let before = file.accounts.len();
        file.accounts.retain(|a| a.id != id);
        if file.accounts.len() == before {
            return Ok(false);
        }
        if file.active.as_deref() == Some(id) {
            file.active = file.accounts.first().map(|a| a.id.clone());
        }
        self.save(channel, &file)?;
        if file.accounts.is_empty() {
            // No credentials left: the materialized jar must not outlive them.
            let _ = fs::remove_file(self.jar_path(channel));
        }
        Ok(true)
    }

    /// Drop every account of a channel.
    pub fn clear(&self, channel: &str) -> Result<usize> {
        let file = self.load(channel)?;
        let removed = file.accounts.len();
        if removed == 0 {
            return Ok(0);
        }
        self.save(channel, &AccountFile::default())?;
        let _ = fs::remove_file(self.jar_path(channel));
        Ok(removed)
    }

    /// Record the outcome of a status probe on one account.
    pub fn record_check(&self, channel: &str, id: &str, status: AccountStatus) -> Result<()> {
        let mut file = self.load(channel)?;
        let now = now_ms();
        let Some(account) = file.accounts.iter_mut().find(|a| a.id == id) else {
            return Err(Error::channel(format!("no account {id} for channel {channel}")));
        };
        account.status = status;
        account.updated_at = now;
        if matches!(status, AccountStatus::Active) {
            account.last_checked_at = now;
        }
        self.save(channel, &file)
    }

    /// Netscape text of one account. SECRET — do not log.
    pub fn cookies_for(&self, channel: &str, id: &str) -> Result<String> {
        Ok(self.get(channel, id)?.cookies)
    }

    /// Write an account's cookies to the materialized jar file (0600).
    ///
    /// Returns the path to hand to a downloader. SECRET content — the path is
    /// fine to log, the file is not.
    pub fn materialize(&self, channel: &str, id: &str) -> Result<PathBuf> {
        let cookies_text = self.cookies_for(channel, id)?;
        self.ensure_dirs()?;
        let path = self.jar_path(channel);
        fs::write(&path, cookies_text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    /// Delete expired session files. Called opportunistically; a stale session
    /// is also rejected on read, so this is housekeeping, not correctness.
    pub fn sweep_sessions(&self, ttl_ms: i64) -> Result<usize> {
        let dir = self.sessions_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };
        let now = now_ms();
        let mut swept = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let expired = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .and_then(|v| v.get("createdAt")?.as_i64())
                .map(|created| now - created > ttl_ms)
                .unwrap_or(true);
            if expired {
                let _ = fs::remove_file(&path);
                swept += 1;
            }
        }
        Ok(swept)
    }
}

/// Legacy `cookies/<site>.json` record from dsh-video-fetch ≤0.2.
#[derive(Debug, Clone, serde::Deserialize)]
struct LegacyJar {
    #[serde(default)]
    source: String,
    #[serde(default)]
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(default)]
    data: String,
}

/// Convenience re-export so callers can build a `HashMap` of channels without
/// importing `std::collections` themselves.
pub type ChannelMap<T> = HashMap<String, T>;
