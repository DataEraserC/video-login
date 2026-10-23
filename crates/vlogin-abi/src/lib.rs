//! C ABI over `vlogin-core`.
//!
//! One entry point, `vlogin_call`, plus the `vlogin_string_free` it hands
//! ownership to. Both sides speak JSON, which keeps the FFI surface at three
//! functions and means a host binding is a dozen lines of koffi rather than a
//! hand-written struct mirror of the whole model.
//!
//! ```c
//! char *out = vlogin_call("{\"op\":\"channels\"}");
//! /* … */
//! vlogin_string_free(out);
//! ```
//!
//! ## Memory contract
//!
//! `vlogin_call` returns a malloc'd, NUL-terminated C string owned by the
//! caller. It must be released with `vlogin_string_free` — freeing it with the
//! host's own `free` is undefined behaviour, because the Rust allocator and the
//! host allocator need not agree. Returning JSON Strings (not `*const c_char`
//! borrows) is what makes that contract expressible.
//!
//! ## Secrets boundary
//!
//! Every response is shaped so that no cookie value ever appears in it. The
//! only op that returns secret text is `export`, and it is meant for writing
//! straight into a downloader's cookie file, not for display.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use serde_json::{json, Value};
use vlogin_core::model::AccountStatus;

/// Run one JSON-encoded operation.
///
/// `request` must be a NUL-terminated UTF-8 string. On a malformed request the
/// response is `{"ok":false,"error":{...}}` rather than a null pointer, so a
/// host always has something printable.
///
/// # Safety
///
/// `request` must be a valid pointer to a NUL-terminated C string, or null (in
/// which case an error response is returned).
#[no_mangle]
pub unsafe extern "C" fn vlogin_call(request: *const c_char) -> *mut c_char {
    let text = if request.is_null() {
        return to_ptr(error_response("abi", "null request pointer"));
    } else {
        match CStr::from_ptr(request).to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return to_ptr(error_response("abi", "request is not valid UTF-8")),
        }
    };

    let response = match serde_json::from_str::<Value>(&text) {
        Ok(request) => dispatch(&request),
        Err(error) => error_response("bad_request", &error.to_string()),
    };
    to_ptr(response)
}

/// Release a string returned by [`vlogin_call`]. Accepts null.
///
/// # Safety
///
/// The pointer must have come from `vlogin_call` and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn vlogin_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    drop(CString::from_raw(value));
}

/// Library version, for host diagnostics.
///
/// # Safety
///
/// Takes no arguments; the returned pointer must be freed with
/// [`vlogin_string_free`].
#[no_mangle]
pub unsafe extern "C" fn vlogin_version() -> *mut c_char {
    to_ptr(json!({ "ok": true, "result": env!("CARGO_PKG_VERSION") }))
}

/// Hand a JSON value back to C as an owned C string.
fn to_ptr(value: Value) -> *mut c_char {
    match CString::new(value.to_string()) {
        Ok(text) => text.into_raw(),
        Err(_) => {
            // `to_string()` never emits NUL for the values we build, so this
            // is a defensive branch rather than an expected one.
            ptr::null_mut()
        }
    }
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
fn dispatch(request: &Value) -> Value {
    let op = match request.get("op").and_then(|v| v.as_str()) {
        Some(op) => op,
        None => return error_response("bad_request", "missing 'op'"),
    };

    let result = (|| -> vlogin_core::Result<Value> {
        match op {
            "channels" => {
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.site_channels())?)
            }
            "status" => {
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.statuses())?)
            }
            "accounts" => {
                let channel = require_channel(request)?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.accounts(&channel)?)?)
            }
            "start" => {
                let start: vlogin_core::StartRequest =
                    serde_json::from_value(request.clone())?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.start(&start)?)?)
            }
            "browse" => {
                let channel = require_channel(request)?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.browse(&channel)?)?)
            }
            "poll" => {
                let session_id = require_string(request, "sessionId")?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.poll(&session_id)?)?)
            }
            "submit" => {
                let session_id = require_string(request, "sessionId")?;
                let params = request.get("params").cloned().unwrap_or(Value::Null);
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.submit(&session_id, &params)?)?)
            }
            "import" => {
                let channel = require_channel(request)?;
                let method =
                    require_string_optional(request, "method").unwrap_or_else(|| "manual".into());
                let cookies = require_string(request, "cookies")?;
                let label = require_string_optional(request, "label").unwrap_or_default();
                let hub = vlogin_core::Hub::open_default()?;
                let view = hub.import(&channel, &method, &cookies, &label)?;
                Ok(serde_json::to_value(view)?)
            }
            "check" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = vlogin_core::Hub::open_default()?;
                let view = hub.status(&channel, account.as_deref())?;
                Ok(serde_json::to_value(view)?)
            }
            "pin" => {
                let channel = require_channel(request)?;
                let account = require_string(request, "account")?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(serde_json::to_value(hub.pin(&channel, &account)?)?)
            }
            "logout" => {
                let channel = require_channel(request)?;
                let account = require_string(request, "account")?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(json!({ "removed": hub.logout(&channel, &account)? }))
            }
            "clear" => {
                let channel = require_channel(request)?;
                let hub = vlogin_core::Hub::open_default()?;
                Ok(json!({ "removed": hub.clear(&channel)? }))
            }
            "export" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = vlogin_core::Hub::open_default()?;
                Ok(json!({ "cookies": hub.export(&channel, account.as_deref())? }))
            }
            "materialize" => {
                let channel = require_channel(request)?;
                let account = require_string_optional(request, "account");
                let hub = vlogin_core::Hub::open_default()?;
                Ok(json!({ "path": hub.materialize(&channel, account.as_deref())? }))
            }
            "cancel" => {
                let session_id = require_string(request, "sessionId")?;
                let hub = vlogin_core::Hub::open_default()?;
                hub.cancel(&session_id)?;
                Ok(json!({ "cancelled": true }))
            }
            "sweep" => {
                let hub = vlogin_core::Hub::open_default()?;
                Ok(json!({ "swept": hub.sweep()? }))
            }
            other => Err(vlogin_core::Error::channel(format!("unknown op '{other}'"))),
        }
    })();

    match result {
        Ok(value) => ok(value),
        Err(error) => error_response(error_kind(&error), &error.to_string()),
    }
}

/// Map an error onto the stable `kind` string hosts switch on.
fn error_kind(error: &vlogin_core::Error) -> &'static str {
    match error {
        vlogin_core::Error::Channel(_) => "channel",
        vlogin_core::Error::Cookie(_) => "cookie",
        vlogin_core::Error::Http(_) => "http",
        vlogin_core::Error::Io(_) => "io",
        vlogin_core::Error::Json(_) => "json",
        vlogin_core::Error::Other(_) => "other",
    }
}

/// Read the `channel` field.
fn require_channel(request: &Value) -> vlogin_core::Result<String> {
    require_string(request, "channel")
}

/// Read a required string field.
fn require_string(request: &Value, key: &str) -> vlogin_core::Result<String> {
    request
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| vlogin_core::Error::channel(format!("missing '{key}'")))
}

/// Read an optional string field.
fn require_string_optional(request: &Value, key: &str) -> Option<String> {
    request.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Human labels for account status, so hosts need no lookup table.
#[allow(dead_code)]
fn status_label(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Unknown => "unknown",
        AccountStatus::Active => "active",
        AccountStatus::Expired => "expired",
        AccountStatus::Unreachable => "unreachable",
    }
}
