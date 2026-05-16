//! ADR-002 Ratification Criterion C7 — trust-bearing consumers must not
//! bypass the strategy-bearing digest API by pairing a vr-jcs
//! canonical-bytes function with a direct `blake3::*` primitive in the
//! same file.
//!
//! This is the file-pairing heuristic for the ADR-002 § Security
//! Considerations "Bypass via bare `blake3::hash`" hazard. ADR-002 §
//! Ratification Criteria § C7 scope defines the deny / allow boundary.
//!
//! **Deny condition (receipt-bypass pairing):** a `.rs` file in a
//! trust-bearing consumer crate contains BOTH
//!
//! - a reference to a vr-jcs canonical-bytes producer
//!   (`to_canon_bytes_from_slice`, `to_canon_string_from_str`,
//!   `to_canon_bytes`, `to_canon_string`, `canonical_bytes_from_slice`),
//!   AND
//! - a direct call to a BLAKE3 spec primitive
//!   (`blake3::hash(`, `blake3::keyed_hash(`, `blake3::derive_key(`).
//!
//! That pairing in one translation unit is the receipt-bypass shape
//! ADR-002 binds as forbidden.
//!
//! **Allowlist:** file paths matching any of `ALLOWLIST_PATH_FRAGMENTS`
//! are skipped. Test files asserting spec conformance go through this
//! mechanism; intentional legacy bypasses get a path entry plus a
//! one-line reason. New entries SHOULD be exceptional and should carry
//! a tracking comment.
//!
//! Trust-bearing consumers (extend as new consumers are admitted):
//! `vertrule-schemas`, `vertrule-verifier`. When a consumer directory
//! is absent (vr-jcs tested in isolation), the check is skipped.
//!
//! Findings are emitted as **structured records** (file, line, pattern)
//! so the assertion message is parseable rather than free-text.

use std::path::{Path, PathBuf};

const TRUST_BEARING_CONSUMER_DIRS: &[&str] = &[
    "../vertrule-schemas/src",
    "../vertrule-verifier/src",
];

const CANONICAL_BYTES_PATTERNS: &[&str] = &[
    // Fully-qualified vr-jcs strict-path producers.
    "vr_jcs::to_canon_bytes_from_slice",
    "vr_jcs::to_canon_string_from_str",
    "vr_jcs::canonical_bytes_from_slice",
    // Bare call-site patterns for the strict-path producers. These names
    // are unique to vr-jcs in this workspace; a bare `(`-suffix call
    // identifies the same function via post-import call sites.
    "to_canon_bytes_from_slice(",
    "to_canon_string_from_str(",
    "canonical_bytes_from_slice(",
    // The deprecated typed-path producers are already covered by
    // ADR-001 Criterion #9 (`no_trust_typed_jcs.rs`). Excluding them
    // here keeps C7 focused on strict-path + bare-BLAKE3 pairings and
    // avoids false positives from consumer types whose methods are
    // coincidentally named `to_canon_bytes` / `to_canon_string` (e.g.
    // `Bundle::to_canon_bytes(&self)` in `vertrule-verifier`).
];

const BLAKE3_PRIMITIVE_PATTERNS: &[&str] = &[
    "blake3::hash(",
    "blake3::keyed_hash(",
    "blake3::derive_key(",
];

/// Path fragments that suppress the C7 finding. Each entry is a path
/// substring; matching files are skipped. Order is informational only.
///
/// Add entries with a `// TODO(ADR-002-C7)` comment explaining the
/// legacy reason and the migration plan. New entries SHOULD be rare.
const ALLOWLIST_PATH_FRAGMENTS: &[&str] = &[
    // Tests asserting BLAKE3 spec conformance are explicitly admitted
    // (ADR-002 C7 § Allowed: "tests explicitly asserting spec conformance").
    "verify_tests.rs",
    "signature_tests.rs",
    "bundle_tests.rs",
    "rbh_tests.rs",
    // TODO(ADR-002-C7): migrate `vertrule-verifier/src/bundle.rs` digest
    // computation to `to_canon_digest_with` or `to_canon_blake3_digest`
    // so receipt-bound code paths carry algorithm-with-output via
    // `CanonicalDigest`.
    "vertrule-verifier/src/bundle.rs",
    // TODO(ADR-002-C7): migrate `vertrule-verifier/src/rbh.rs` digest
    // computation to the strategy-bearing API. RBH event hashes feed
    // receipts; bypass risks algorithm misattribution.
    "vertrule-verifier/src/rbh.rs",
    // TODO(ADR-002-C7): migrate `vertrule-schemas/src/receipts/commitment.rs`
    // commitment digest to the strategy-bearing API.
    "vertrule-schemas/src/receipts/commitment.rs",
    // TODO(ADR-002-C7): migrate `vertrule-schemas/src/governance/decision.rs`
    // surface-decision and binding-id digests to the strategy-bearing API.
    "vertrule-schemas/src/governance/decision.rs",
    // TODO(ADR-002-C7): migrate `vertrule-verifier/src/wasm.rs` digest
    // computation (5 blake3::hash call sites paired with strict-path
    // canonicalization) to the strategy-bearing API. The WASM surface
    // emits receipt-equivalent material to consumers; algorithm-with-output
    // binding must travel with it.
    "vertrule-verifier/src/wasm.rs",
];

struct Finding {
    path: PathBuf,
    canonical_pattern: &'static str,
    canonical_line: usize,
    blake3_pattern: &'static str,
    blake3_line: usize,
}

fn is_allowlisted(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    ALLOWLIST_PATH_FRAGMENTS
        .iter()
        .any(|fragment| path_str.contains(fragment))
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

fn scan_file(path: &Path) -> std::io::Result<Option<Finding>> {
    let content = std::fs::read_to_string(path)?;
    let mut canonical: Option<(&'static str, usize)> = None;
    let mut blake3_primitive: Option<(&'static str, usize)> = None;

    for (zero_based, line) in content.lines().enumerate() {
        if canonical.is_none() {
            for pattern in CANONICAL_BYTES_PATTERNS {
                if line.contains(pattern) {
                    canonical = Some((pattern, zero_based + 1));
                    break;
                }
            }
        }
        if blake3_primitive.is_none() {
            for pattern in BLAKE3_PRIMITIVE_PATTERNS {
                if line.contains(pattern) {
                    blake3_primitive = Some((pattern, zero_based + 1));
                    break;
                }
            }
        }
        if canonical.is_some() && blake3_primitive.is_some() {
            break;
        }
    }

    match (canonical, blake3_primitive) {
        (Some((canonical_pattern, canonical_line)), Some((blake3_pattern, blake3_line))) => {
            Ok(Some(Finding {
                path: path.to_path_buf(),
                canonical_pattern,
                canonical_line,
                blake3_pattern,
                blake3_line,
            }))
        }
        _ => Ok(None),
    }
}

#[test]
fn no_receipt_bypass_pairing_in_trust_bearing_consumers() -> std::io::Result<()> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut directories_checked: usize = 0;

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
            if let Some(finding) = scan_file(&path)? {
                findings.push(finding);
            }
        }
    }

    if directories_checked == 0 {
        return Ok(());
    }

    let formatted = findings
        .iter()
        .map(|f| {
            format!(
                "  {} pairs `{}` (line {}) with `{}` (line {})",
                f.path.display(),
                f.canonical_pattern,
                f.canonical_line,
                f.blake3_pattern,
                f.blake3_line,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let count = findings.len();

    assert!(
        findings.is_empty(),
        "Found {count} receipt-bypass pairing(s) in trust-bearing consumers:\n{formatted}",
    );

    Ok(())
}
