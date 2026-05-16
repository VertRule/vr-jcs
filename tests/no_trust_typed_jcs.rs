//! ADR-001 Ratification Criterion #9 — no trust-bearing consumer uses
//! the deprecated typed JCS path.
//!
//! Greps known trust-bearing consumer crates for textual references to
//! the symbols `vr_jcs::to_canon_bytes` and `vr_jcs::to_canon_string`,
//! the deprecated typed-path functions. The `_from_slice` / `_from_str`
//! siblings are excluded — they are the non-deprecated strict-path entry
//! points and remain admitted everywhere.
//!
//! Trust-bearing consumers in this workspace (extend this list as new
//! consumers are admitted):
//!
//! - `vertrule-schemas`
//! - `vertrule-verifier`
//!
//! When a directory is absent (e.g. vr-jcs being tested in isolation
//! outside the `VertRule` workspace), that consumer is silently skipped.
//! The test fails ONLY when a present consumer references the deprecated
//! typed path.
//!
//! Allowlist heuristic: paths containing `deprecated` anywhere in the
//! filename or directory chain are skipped. This covers vr-jcs's own
//! `tests/deprecated_typed_api.rs` and any equivalently-named regression
//! tests inside consumer crates.
//!
//! Per ADR-001 § Security Considerations, the `#[deprecated]` annotation
//! alone is insufficient because consumers may locally
//! `#[allow(deprecated)]`. This file enforces the
//! trust-bearing-no-typed-path rule textually as a workspace-level CI gate.

use std::path::{Path, PathBuf};

const TRUST_BEARING_CONSUMER_DIRS: &[&str] = &[
    "../vertrule-schemas/src",
    "../vertrule-verifier/src",
];

fn line_has_typed_path_violation(line: &str) -> Option<&'static str> {
    if line.contains("vr_jcs::to_canon_bytes")
        && !line.contains("vr_jcs::to_canon_bytes_from_slice")
    {
        return Some("vr_jcs::to_canon_bytes (deprecated typed path)");
    }
    if line.contains("vr_jcs::to_canon_string")
        && !line.contains("vr_jcs::to_canon_string_from_str")
    {
        return Some("vr_jcs::to_canon_string (deprecated typed path)");
    }
    None
}

fn is_allowlisted(path: &Path) -> bool {
    path.to_string_lossy().contains("deprecated")
}

fn walk_rust_sources(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_rust_sources(&path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn no_trust_bearing_consumer_calls_typed_path() -> std::io::Result<()> {
    let mut violations: Vec<(PathBuf, usize, &'static str)> = Vec::new();
    let mut directories_checked = 0_usize;

    for dir_relative in TRUST_BEARING_CONSUMER_DIRS {
        let root = Path::new(dir_relative);
        if !root.exists() {
            continue;
        }
        directories_checked += 1;

        let mut files = Vec::new();
        walk_rust_sources(root, &mut files)?;

        for path in files {
            if is_allowlisted(&path) {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            for (zero_based, line) in content.lines().enumerate() {
                if let Some(pattern) = line_has_typed_path_violation(line) {
                    violations.push((path.clone(), zero_based + 1, pattern));
                }
            }
        }
    }

    if directories_checked == 0 {
        // vr-jcs being tested in isolation — no workspace siblings on disk.
        return Ok(());
    }

    let formatted = violations
        .iter()
        .map(|(p, line, pat)| format!("  {}:{} matches `{}`", p.display(), line, pat))
        .collect::<Vec<_>>()
        .join("\n");
    let count = violations.len();

    assert!(
        violations.is_empty(),
        "Found {count} typed-path violation(s) in trust-bearing consumers:\n{formatted}",
    );

    Ok(())
}
