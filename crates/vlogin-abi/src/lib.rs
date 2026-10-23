//! C ABI over `vlogin-core`.
//!
//! One entry point, `vlogin_call`, plus `vlogin_version` for diagnostics. Both
//! sides speak JSON, so the FFI surface stays at two functions and a host binding
//! is a dozen lines of koffi rather than a hand-written struct mirror of the
//! whole model.
//!
//! ## Memory contract — caller-allocated output
//!
//! ```c
//! char buf[1 << 20];
//! int64_t needed = vlogin_call("{\"op\":\"channels\"}", buf, sizeof buf);
//! ```
//!
//! The caller owns the output buffer; Rust only writes into it. There is
//! deliberately **no** `vlogin_string_free`. The obvious alternative —
//! returning a Rust-allocated C string for the host to free — demands that the
//! host's allocator and Rust's agree, and every forgetful binding leaks. A
//! caller-owned buffer has neither problem; the only cost is one extra call if
//! the first buffer was too small.
//!
//! Return value is always the size the response occupies **including** the
//! trailing NUL:
//!
//! * `> 0` — response length. It was copied into `out` only if it fit;
//!   otherwise grow the buffer to this size and call again.
//! * `-1` — `request` was null or not valid UTF-8.
//!
//! ## Secrets boundary
//!
//! Every response is shaped so no cookie value appears in it. The only op that
//! returns secret text is `export`, and it exists to be written straight into a
//! downloader's cookie file, not to be displayed.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use serde_json::{json, Value};
use vlogin_core::{Error, Hub, StartRequest};

/// Run one JSON-encoded operation.
///
/// `request` must be a NUL-terminated UTF-8 string; `out`/`out_len` describe a
/// caller-owned buffer the JSON response is written into, NUL included.
///
/// # Safety
///
/// `request` must be a valid pointer to a NUL-terminated C string (or null).
/// `out` must be null or point to at least `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn vlogin_call(
    request: *const c_char,
    out: *mut c_char,
    out_len: u64,
) -> i64 {
    if request.is_null() {
        return -1;
    }
    let text = match CStr::from_ptr(request).to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };

    let response = match serde_json::from_str::<Value>(text) {
        Ok(parsed) => dispatch(&parsed),
        Err(error) => error_response("bad_request", &error.to_string()),
    };

    let encoded = response.to_string();
    // +1 for the NUL terminator.
    let needed = encoded.len() + 1;
    if !out.is_null() && needed <= out_len as usize {
        let bytes = encoded.as_bytes();
        ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    needed as i64
}

/// Library version, for host diagnostics.
///
/// Points at a `'static` array, so the pointer stays valid forever and must
/// **not** be freed.
#[no_mangle]
pub extern "C" fn vlogin_version() -> *const c_char {
    b"0.1.0\0".as_ptr() as *const c_char
}

/// A failed operation, tagged with a stable machine-readable `kind`.
fn error_response(kind: &str, message: &str) -> Value {
    json!({ "ok": false, "error": { "kind": kind, "message": message } })
}

/// A successful operation.
fn ok(result: Value) -> Value {
    json!({ "ok": true, "result": result })
}

/// Route one request to its handler.
///
/// ## Ops
///
/// * `channels` — every advertised channel, with display name and methods.
/// * `route`    — `{ url }` → `{ channel }`: which channel owns that URL.
/// * `status`   — every channel with its account pool and pinned account id.
/// * `accounts` — `{ channel }` → that channel's accounts, pinned first.
/// * `start`    — `{ channel, method, params?, label? }` → `{ session_id, challenge }`.
/// * `browse`   — `{ channel }` → `{ session_id, challenge }` (real browser).
/// * `poll`     — `{ sessionId }` → `{ result, account? }`.
/// * `submit`   — `{ sessionId, params }` → `{ result, account? }`.
/// * `import`   — `{ channel, cookies, label? }` → `{ account }`.
/// * `check`    — `{ channel, account? }` → `{ account }` (probes the site).
/// * `pin`      — `{ channel, account }` → `{ account }`.
/// * `logout`   — `{ channel, account }` → `{ removed }`.
/// * `clear`    — `{ channel }` → `{ removed }`.
/// * `cancel`   — `{ sessionId }` → `{ cancelled }`.
/// * `export`   — `{ channel, account? }` → `{ cookies }`. SECRET: the only
///   response carrying cookie text.
/// * `materialize` — `{ channel, account? }` → `{ path }` of a 0600 cookie file.
/// * `sweep`  — deletes expired login sessions.
///
/// The closure wrapper is what lets every arm use `?` for both the core's own
/// errors and `serde_json`'s while agreeing on one return type.
fn dispatch(request: &Value) -> Value {
    let op = match request.get("op").and_then(|v| v.as_str()) {
        Some(op) => op,
        None => return error_response("bad_request", "missing 'op'"),
    };

    let result = (|| -> Result<Value, Error> {
        match op {
            "channels" => {
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.site_channels())?)
            }
            "route" => {
                let url = require_string(request, "url")?;
                let hub = Hub::open_default()?;
                Ok(json!({ "channel": hub.channel_for_url(&url) }))
            }
            "status" => {
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.statuses())?)
            }
            "accounts" => {
                let channel = require_channel(request)?;
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.accounts(&channel)?)?)
            }
            "start" => {
                let start: StartRequest = serde_json::from_value(request.clone())?;
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.start(&start)?)?)
            }
            "browse" => {
                let channel = require_channel(request)?;
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.browse(&channel)?)?)
            }
            "poll" => {
                let session_id = require_string(request, "sessionId")?;
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.poll(&session_id)?)?)
            }
            "submit" => {
                let session_id = require_string(request, "sessionId")?;
                let params = request.get("params").cloned().unwrap_or(Value::Null);
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.submit(&session_id, &params)?)?)
            }
            "import" => {
                let channel = require_channel(request)?;
                let method =
                    require_string_optional(request, "method").unwrap_or_else(|| "manual".into());
                let cookies = require_string(request, "cookies")?;
                let label = require_string_optional(request, "label").unwrap_or_default();
                let hub = Hub::open_default()?;
                let view = hub.import(&channel, &method, &cookies, &label)?;
                Ok(serde_json::to_value(view)?)
            }
            "check" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = Hub::open_default()?;
                let view = hub.status(&channel, account.as_deref())?;
                Ok(serde_json::to_value(view)?)
            }
            "pin" => {
                let channel = require_channel(request)?;
                let account = require_string(request, "account")?;
                let hub = Hub::open_default()?;
                Ok(serde_json::to_value(hub.pin(&channel, &account)?)?)
            }
            "logout" => {
                let channel = require_channel(request)?;
                let account = require_string(request, "account")?;
                let hub = Hub::open_default()?;
                // Bare bool, not `{ removed: bool }`: the ABI envelope already
                // is the wrapper, so a second one would nest and every host
                // binding would have to know to unwrap twice.
                Ok(json!(hub.logout(&channel, &account)?))
            }
            "clear" => {
                let channel = require_channel(request)?;
                let hub = Hub::open_default()?;
                Ok(json!(hub.clear(&channel)?))
            }
            "export" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = Hub::open_default()?;
                Ok(json!({ "cookies": hub.export(&channel, account.as_deref())? }))
            }
            "materialize" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = Hub::open_default()?;
                Ok(json!({ "path": hub.materialize(&channel, account.as_deref())? }))
            }
            "cancel" => {
                let session_id = require_string(request, "sessionId")?;
                let hub = Hub::open_default()?;
                hub.cancel(&session_id)?;
                Ok(json!({ "cancelled": true }))
            }
            "sweep" => {
                let hub = Hub::open_default()?;
                Ok(json!({ "swept": hub.sweep()? }))
            }
            other => Err(Error::channel(format!("unknown op '{other}'"))),
        }
    })();

    match result {
        Ok(value) => ok(value),
        Err(error) => error_response(error_kind(&error), &error.to_string()),
    }
}

/// Map an error onto the stable `kind` string hosts switch on.
fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Channel(_) => "channel",
        Error::Cookie(_) => "cookie",
        Error::Http(_) => "http",
        Error::Io(_) => "io",
        Error::Json(_) => "json",
        Error::Other(_) => "other",
    }
}

/// Read the `channel` field, which most ops carry.
fn require_channel(request: &Value) -> Result<String, Error> {
    require_string(request, "channel")
}

/// Read a required string field.
fn require_string(request: &Value, key: &str) -> Result<String, Error> {
    request
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::channel(format!("missing '{key}'")))
}

/// Read an optional string field.
fn require_string_optional(request: &Value, key: &str) -> Option<String> {
    request.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}
