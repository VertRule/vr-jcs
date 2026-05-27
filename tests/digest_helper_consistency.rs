//! ADR-002 Ratification Criterion C5 — fixed-policy BLAKE3 helpers
//! produce the same digest bytes as the strategy-bearing path with
//! `DigestStrategy::blake3_untagged()`.
//!
//! Pins two consistency invariants:
//!
//! 1. `to_canon_blake3_digest(value)` byte-equals
//!    `to_canon_digest_with(value, blake3_untagged()).bytes`. A future
//!    refactor that diverges these (e.g. accidentally introducing
//!    different padding, length encoding, or pre-hash prefix) is
//!    detected here.
//! 2. `to_canon_blake3_digest_from_slice(json)` byte-equals
//!    `to_canon_blake3_digest(strict_parsed_value)`. The strict-parse +
//!    fixed-policy convenience path produces the same digest as the
//!    two-step (strict-parse, then Value-input helper) path.

use vr_jcs::{
    strict_parse, to_canon_blake3_digest, to_canon_blake3_digest_from_slice, to_canon_digest_with,
    DigestStrategy, JcsError,
};

#[test]
fn fixed_helper_and_strategy_yield_same_bytes_on_value() -> Result<(), JcsError> {
    let value = serde_json::json!({"alpha": 1, "beta": [2, 3]});

    let fixed: [u8; 32] = to_canon_blake3_digest(&value)?;
    let strategy = to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;

    assert_eq!(strategy.bytes.len(), 32);
    assert_eq!(
        strategy.bytes.as_slice(),
        fixed.as_slice(),
        "to_canon_blake3_digest must equal to_canon_digest_with(blake3_untagged).bytes",
    );
    Ok(())
}

#[test]
fn fixed_from_slice_helper_matches_value_helper_after_strict_parse() -> Result<(), JcsError> {
    let json: &[u8] = br#"{"alpha":1,"beta":[2,3]}"#;

    let from_slice: [u8; 32] = to_canon_blake3_digest_from_slice(json)?;

    let parsed = strict_parse::parse_json_value_no_duplicates(json)?;
    let from_value: [u8; 32] = to_canon_blake3_digest(&parsed)?;

    assert_eq!(
        from_slice, from_value,
        "to_canon_blake3_digest_from_slice must equal \
         to_canon_blake3_digest on the strict-parsed value",
    );
    Ok(())
}
