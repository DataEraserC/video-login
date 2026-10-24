//! The core names no harness.
//!
//! `vlogin-core` is reached through a C ABI so that a CLI, a dsh plugin or a
//! Python script can all use it. That promise is only worth something if the
//! crate keeps no knowledge of any of its callers — and the easiest way to
//! lose it is a convenience. A fallback to "wherever that one harness puts its
//! state" reads as a courtesy to that harness and works fine until a second
//! caller inherits it by accident, at which point the CLI's data lands inside
//! someone else's directory.
//!
//! This test scans every production source of the crate and fails when a
//! harness-specific token appears in code, so the boundary cannot erode
//! silently. Comments are stripped: recording that a module was ported out of
//! `dsh-video-fetch` is history, not a dependency.

use std::fs;
use std::path::{Path, PathBuf};

/// Tokens that must never appear in `vlogin-core` code.
///
/// `dsh` alone would match nothing useful and too much else, so these are the
/// forms a real dependency takes: an environment variable, a package prefix, or
/// the name of the vendor.
const FORBIDDEN: &[&str] = &["DSH_HOME", "dsh-", "dsh_", "deepseek", "cordis"];

/// Drop `//` line comments, ignoring `//` that lives inside a string literal
/// (the crate carries full URLs, e.g. `https://…`).
fn strip_comments(line: &str) -> String {
    let mut in_string = false;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '/' && chars.get(index + 1) == Some(&'/') {
            return chars[..index].iter().collect();
        }
        index += 1;
    }
    line.to_string()
}

fn collect_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn core_names_no_harness() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_sources(&root, &mut files);
    assert!(!files.is_empty(), "no sources found under {}", root.display());

    let mut violations = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string();
        // `#[cfg(test)]` modules may name anything: they are not part of the
        // library that ships.
        let mut in_tests = false;
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("#[cfg(test)]") {
                in_tests = true;
            }
            if in_tests {
                continue;
            }
            let code = strip_comments(line);
            for token in FORBIDDEN {
                if code.contains(token) {
                    violations.push(format!("{relative}:{}: `{token}`", index + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "vlogin-core must not name a harness: it is reached through a C ABI and \
         is used by a CLI as well as by the dsh plugin. A harness-specific \
         default belongs in the adapter, which exports it into VLOGIN_HOME:\n  {}",
        violations.join("\n  ")
    );
}
