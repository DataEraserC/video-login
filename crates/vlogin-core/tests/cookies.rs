//! Netscape cookie codec tests.
//!
//! These cover the codec that used to live in the dsh-video-fetch plugin's
//! `lib/cookies.js`. It moved here with the rest of the credential machinery,
//! so the tests moved with it: the logic under test is now Rust, and testing a
//! port from the JS side would only prove the FFI round-trips.

use vlogin_core::cookies::{
    count_netscape_cookies, header_from_netscape, parse_http_date, parse_netscape,
    parse_set_cookies, to_netscape,
};

#[test]
fn parse_set_cookies_reads_attributes_and_defaults() {
    let cookies = parse_set_cookies(&[
        "SESSDATA=abc%2C1; Domain=.bilibili.com; Expires=Wed, 01 Jan 2027 00:00:00 GMT; Path=/; HttpOnly; Secure".to_string(),
        "sid=plainvalue; Path=/; Max-Age=60".to_string(),
    ]);
    assert_eq!(cookies.len(), 2);

    assert_eq!(cookies[0].name, "SESSDATA");
    assert_eq!(cookies[0].domain, ".bilibili.com");
    assert_eq!(cookies[0].path, "/");
    assert!(cookies[0].secure);
    assert!(cookies[0].http_only);
    assert!(cookies[0].expires > 1_700_000_000, "Expires parsed to unix seconds");

    // No Domain= → empty, and the caller's fallback domain applies later.
    assert_eq!(cookies[1].domain, "");
    assert_eq!(cookies[1].path, "/");
    assert!(!cookies[1].secure);
    assert!(!cookies[1].http_only);
    // Max-Age is relative to now, so it must land within a second or two.
    let expected = vlogin_core::cookies::now_unix() + 60;
    assert!((cookies[1].expires - expected).abs() <= 5, "Max-Age wins over Expires");
}

#[test]
fn parse_set_cookies_skips_malformed_lines() {
    let cookies = parse_set_cookies(&[
        "".to_string(),
        "=novalue".to_string(),          // empty name
        "noequalsign".to_string(),       // not a pair at all
        "ok=1".to_string(),
    ]);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "ok");
}

#[test]
fn parse_http_date_accepts_rfc7231_and_rejects_garbage() {
    let parsed = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(parsed, 784_111_777);

    // Malformed input is 0 rather than an error: a cookie with an unparseable
    // expiry is still a cookie, and 0 already means "session cookie".
    assert_eq!(parse_http_date("not a date"), 0);
    assert_eq!(parse_http_date(""), 0);
}

#[test]
fn to_netscape_writes_standard_rows_and_keeps_httponly_marker() {
    let cookies = parse_set_cookies(&[
        "SESSDATA=abc,1; Domain=.bilibili.com; Path=/; HttpOnly; Secure".to_string(),
        "bili_jct=tok; Domain=.bilibili.com; Path=/".to_string(),
    ]);
    let file = to_netscape(&cookies, "bilibili.com");

    let lines: Vec<&str> = file.split('\n').collect();
    assert_eq!(lines[0], "# Netscape HTTP Cookie File");
    // The HttpOnly prefix is the only signal that survives the round-trip, and
    // dropping it would silently downgrade a cookie's protection.
    assert!(lines[1].starts_with("#HttpOnly_.bilibili.com\tTRUE\t/\tTRUE\t0\tSESSDATA\tabc,1"));
    assert!(lines[2].starts_with(".bilibili.com\tTRUE\t/\tFALSE\t0\tbili_jct\ttok"));
}

#[test]
fn header_from_netscape_round_trips_and_tolerates_junk() {
    let text = [
        "# Netscape HTTP Cookie File",
        "# a comment, not a cookie",
        ".bilibili.com\tTRUE\t/\tTRUE\t0\tSESSDATA\tv1",
        "#HttpOnly_.bilibili.com\tTRUE\t/\tTRUE\t0\tbili_jct\tv2",
        "",
    ]
    .join("\n");

    assert_eq!(count_netscape_cookies(&text), 2);
    assert_eq!(header_from_netscape(&text), "SESSDATA=v1; bili_jct=v2");
    assert_eq!(count_netscape_cookies("hello world"), 0);
    assert_eq!(count_netscape_cookies(""), 0);
    assert_eq!(header_from_netscape(""), "");
}

#[test]
fn parse_netscape_inverts_to_netscape() {
    let text = [
        "# Netscape HTTP Cookie File",
        ".bilibili.com\tTRUE\t/\tTRUE\t0\tSESSDATA\tv1",
        "#HttpOnly_.bilibili.com\tTRUE\t/\tFALSE\t0\tbili_jct\tv2",
        "",
    ]
    .join("\n");

    let cookies = parse_netscape(&text);
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0].name, "SESSDATA");
    assert_eq!(cookies[0].value, "v1");
    assert!(cookies[0].secure);
    assert!(cookies[1].http_only, "the #HttpOnly_ prefix is read back");

    let again = to_netscape(&cookies, "bilibili.com");
    assert_eq!(header_from_netscape(&again), "SESSDATA=v1; bili_jct=v2")
}
