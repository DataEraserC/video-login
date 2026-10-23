//! Netscape cookie codec — a direct port of the dsh-video-fetch JS module
//! (`lib/cookies.js`), minus the on-disk store (that lives in `store.rs`).
//!
//! The wire format is what yt-dlp's `--cookies` reads, and it is also the
//! on-disk representation of an account's cookies. Secrets boundary: callers
//! must never put the output of [`header_from_netscape`] or a jar's `cookies`
//! text into logs, tool results, or HTTP responses to a UI — only counts,
//! labels, and login status leave this module.

/// One parsed cookie record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Empty when the Set-Cookie line carried no `Domain=`.
    pub domain: String,
    pub path: String,
    /// Unix seconds; 0 = session cookie.
    pub expires: i64,
    pub secure: bool,
    pub http_only: bool,
}

/// Parse raw `Set-Cookie` header lines into records.
///
/// Port of `parseSetCookies`: `Max-Age` wins over `Expires`, a missing name
/// skips the line, and unknown attributes are ignored.
pub fn parse_set_cookies(lines: &[String]) -> Vec<Cookie> {
    let mut out = Vec::new();
    for line in lines {
        let mut parts = line.split(';');
        let pair = match parts.next() {
            Some(p) => p,
            None => continue,
        };
        let eq = match pair.find('=') {
            Some(i) if i > 0 => i,
            _ => continue,
        };
        let mut record = Cookie {
            name: pair[..eq].trim().to_string(),
            value: pair[eq + 1..].trim().to_string(),
            domain: String::new(),
            path: "/".to_string(),
            expires: 0,
            secure: false,
            http_only: false,
        };
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let mut kv = attr.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let value = kv.next().unwrap_or("").trim();
            match key.as_str() {
                "domain" => record.domain = value.to_string(),
                "path" => record.path = if value.is_empty() { "/".into() } else { value.to_string() },
                "expires" => {
                    record.expires = parse_http_date(value).max(0);
                }
                "max-age" => max_age = value.parse::<i64>().ok(),
                "secure" => record.secure = true,
                "httponly" => record.http_only = true,
                _ => {}
            }
        }
        if let Some(ma) = max_age {
            let now = now_unix();
            record.expires = (now + ma).max(0);
        }
        if record.name.is_empty() {
            continue;
        }
        out.push(record);
    }
    out
}

/// Parse an RFC-7231 `Expires` date ("Wdy, DD Mon YYYY HH:MM:SS GMT") into
/// unix seconds. Returns 0 on anything unparseable, matching the JS
/// `Date.parse(value) || 0` behaviour closely enough for cookie expiry.
pub fn parse_http_date(value: &str) -> i64 {
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    let value = value.trim();
    let comma = match value.find(',') {
        Some(i) => i,
        None => return 0,
    };
    let rest = value[comma + 1..].trim();
    let mut it = rest.split_whitespace();
    let day: i64 = match it.next().and_then(|d| d.parse().ok()) {
        Some(d) => d,
        None => return 0,
    };
    let mon_s = match it.next() {
        Some(m) => m,
        None => return 0,
    };
    let month = match mon_s.to_ascii_lowercase().as_str() {
        "jan" => 1, "feb" => 2, "mar" => 3, "apr" => 4, "may" => 5, "jun" => 6,
        "jul" => 7, "aug" => 8, "sep" => 9, "oct" => 10, "nov" => 11, "dec" => 12,
        _ => return 0,
    };
    let year: i64 = match it.next().and_then(|y| y.parse().ok()) {
        Some(y) => y,
        None => return 0,
    };
    let mut hms = it.next().unwrap_or("").split(':');
    let hour: i64 = hms.next().and_then(|h| h.parse().ok()).unwrap_or(0);
    let min: i64 = hms.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    let sec: i64 = hms.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec
}

/// Howard Hinnant's days_from_civil: days since 1970-01-01 for a proleptic
/// Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serialize cookies to the Netscape file format.
///
/// `fallback_domain` is used when a record carries no `Domain=` (the request
/// host), matching `toNetscape`.
pub fn to_netscape(cookies: &[Cookie], fallback_domain: &str) -> String {
    let mut lines = vec!["# Netscape HTTP Cookie File".to_string()];
    for c in cookies {
        let domain = if c.domain.is_empty() {
            fallback_domain.to_string()
        } else {
            c.domain.clone()
        };
        let include_sub = if domain.starts_with('.') { "TRUE" } else { "FALSE" };
        let prefix = if c.http_only { "#HttpOnly_" } else { "" };
        lines.push(format!(
            "{prefix}{domain}\t{include_sub}\t{}\t{}\t{}\t{}\t{}",
            if c.path.is_empty() { "/" } else { &c.path },
            if c.secure { "TRUE" } else { "FALSE" },
            c.expires,
            c.name,
            c.value,
        ));
    }
    format!("{}\n", lines.join("\n"))
}

/// Count cookie rows in Netscape text (header/comments excluded).
pub fn count_netscape_cookies(text: &str) -> usize {
    let mut count = 0;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let is_http_only = line.starts_with("#HttpOnly_");
        if line.starts_with('#') && !is_http_only {
            continue;
        }
        let cols = line.trim_start_matches("#HttpOnly_");
        if cols.split('\t').count() >= 7 {
            count += 1;
        }
    }
    count
}

/// Build a `Cookie` request header from Netscape text (`a=b; c=d`).
pub fn header_from_netscape(text: &str) -> String {
    let mut pairs = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // #HttpOnly_ lines still hold real cookies; other comments do not.
        if line.starts_with('#') && !line.starts_with("#HttpOnly_") {
            continue;
        }
        let cols: Vec<&str> = line.trim_start_matches("#HttpOnly_").split('\t').collect();
        if cols.len() >= 7 {
            pairs.push(format!("{}={}", cols[5], cols[6]));
        }
    }
    pairs.join("; ")
}

/// Parse Netscape text back into records (used by the browser-import path and
/// by tests). Malformed rows are skipped; `#HttpOnly_` prefixes are honoured.
pub fn parse_netscape(text: &str) -> Vec<Cookie> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let http_only = line.starts_with("#HttpOnly_");
        if line.starts_with('#') && !http_only {
            continue;
        }
        let cols: Vec<&str> = line.trim_start_matches("#HttpOnly_").split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        // The include-subdomains column is redundant with the leading dot in
        // the domain, so it is dropped here (to_netscape re-derives it).
        let _ = cols[1];
        out.push(Cookie {
            domain: cols[0].to_string(),
            path: cols[2].to_string(),
            secure: cols[3].eq_ignore_ascii_case("TRUE"),
            expires: cols[4].parse().unwrap_or(0),
            name: cols[5].to_string(),
            value: cols[6].to_string(),
            http_only,
        });
    }
    out
}
