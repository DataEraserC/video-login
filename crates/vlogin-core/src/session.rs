//! Pending login challenges.
//!
//! A login is a multi-step conversation: `start` hands back a challenge (a QR
//! payload, a set of credential fields, a URL to open), and the host polls or
//! submits until the credential arrives. The state in between has to outlive a
//! single process — the CLI is one-shot (`vlogin login start` then
//! `vlogin login poll`), and the web route handles each HTTP request in a
//! separate turn — so sessions are persisted as 0600 files under
//! `<root>/sessions/<id>.json`.
//!
//! Secrets boundary: `state` can carry a half-finished credential (an OAuth
//! `code_verifier`, a refresh token). It must stay in the file; never echo it
//! into a challenge, a log, or a tool result.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::store::new_id;

/// How long a pending challenge stays valid.
pub const DEFAULT_TTL_MS: i64 = 5 * 60 * 1000;

/// One in-flight login attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub channel: String,
    pub method: String,
    pub created_at: i64,
    pub ttl_ms: i64,
    /// Provider-owned scratch space. May contain secrets.
    pub state: serde_json::Value,
}

impl Session {
    /// Create a session for `channel`/`method` with the given initial state.
    pub fn create(channel: &str, method: &str, state: serde_json::Value) -> Self {
        Self {
            id: new_id(),
            channel: channel.to_string(),
            method: method.to_string(),
            created_at: crate::store::now_ms(),
            ttl_ms: DEFAULT_TTL_MS,
            state,
        }
    }

    /// True when the session has outlived its TTL.
    pub fn expired(&self) -> bool {
        crate::store::now_ms() - self.created_at > self.ttl_ms
    }

    /// Path of this session's file.
    fn path(&self, dir: &Path) -> std::path::PathBuf {
        dir.join(format!("{}.json", self.id))
    }

    /// Write the session to `dir` (creating it 0700, file 0600).
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        let path = self.path(dir);
        fs::write(&path, serde_json::to_string(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a session by id. `None` when missing, unreadable, or expired.
    pub fn load(dir: &Path, id: &str) -> Result<Option<Self>> {
        // Only hex ids from new_id() are accepted, so a hostile id cannot be
        // used to walk the filesystem.
        if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::channel("malformed session id"));
        }
        let path = dir.join(format!("{id}.json"));
        let Ok(text) = fs::read_to_string(&path) else {
            return Ok(None);
        };
        let Ok(session) = serde_json::from_str::<Self>(&text) else {
            return Ok(None);
        };
        if session.expired() {
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
        Ok(Some(session))
    }

    /// Drop a session file; a missing file is not an error.
    pub fn remove(dir: &Path, id: &str) -> Result<()> {
        let path = dir.join(format!("{id}.json"));
        let _ = fs::remove_file(path);
        Ok(())
    }
}
