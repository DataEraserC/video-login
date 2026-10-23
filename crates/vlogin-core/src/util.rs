//! Small helpers with no home of their own.
//!
//! Deliberately dependency-free: both of these are a handful of lines, and
//! pulling in `base64`/`rand` for them would add two crates to the build graph
//! for something we can state outright.

/// Standard base64 (RFC 4648, with padding).
///
/// Used for turning a site-supplied QR PNG into a data URL, and for the
/// RSA-encrypted password blob bilibili expects.
pub fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b =
            [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Random token drawn from `[a-zA-Z0-9]`, for login-session fingerprints and
/// OAuth `state` values.
///
/// NOT CRYPTOGRAPHIC. It is seeded from the clock and pid and passed through
/// xorshift. That is fine for an opaque correlation value, and would be
/// indefensible for a secret. `state` only needs to be unguessable to the
/// extent that it defeats a drive-by CSRF on a loopback listener — use real
/// `OsRng` if that threat model ever tightens.
pub fn random_token(len: usize) -> String {
    const TABLE: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut x = seed();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push(TABLE[(x % 62) as usize] as char);
    }
    out
}

/// A 64-bit seed from wall clock, process id, and a counter, so two tokens
/// minted in the same nanosecond still differ.
fn seed() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0x243F_6A88_85A3_08D3);

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let pid = u64::from(std::process::id());
    let tick = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut x = nanos ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ tick.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    // A few rounds of splitmix64 so low-entropy inputs (a fresh container with
    // a low pid) still start the xorshift stream somewhere unpredictable.
    for _ in 0..4 {
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^= x >> 31;
    }
    x | 1
}

/// Extract the lower-cased host from an absolute URL.
///
/// Hand-rolled rather than pulled from a crate: the only thing URL routing here
/// needs is a hostname to suffix-match against a channel's host list, and taking
/// `url` as a dependency would drag in the whole ICU/Unicode-IDNA tree for one
/// string operation.
pub fn host_of(input: &str) -> Option<String> {
    let rest = input.split_once("://").map(|(_, rest)| rest).unwrap_or(input);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);
    // Bare IPv6 literals keep their brackets; strip them so suffix matching
    // and comparisons behave the same as for names.
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority)
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Percent-encode a byte slice for use in a query string or form body.
pub fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Append `key=value` to a query string, choosing `?` or `&` as needed.
pub fn push_query(query: &mut String, key: &str, value: &str) {
    query.push_str(if query.is_empty() { "?" } else { "&" });
    query.push_str(&format!("{}={}", urlencode(key), urlencode(value)));
}

/// Current wall clock in milliseconds since the epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Random 16-hex-char id, used for account records.
pub fn new_id() -> String {
    let mut x = seed();
    let mut out = String::with_capacity(16);
    for _ in 0..16 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push_str(&format!("{:x}", (x >> 60) & 0xf));
    }
    out
}
