//! ADR-003 Ratification Criterion C1 — every bound `JcsError` variant
//! returns its exact code string via `JcsError::code()`.
//!
//! Six small tests, one per variant in the registry. Splitting per
//! variant makes a failure immediately attributable rather than buried
//! in a multi-assertion test body.
//!
//! Code strings are pinned by ADR-003 § Decision item 4. Renaming or
//! removing any of these is a breaking change requiring a superseding
//! ADR.

use vr_jcs::JcsError;

#[test]
fn json_variant_code_is_json_parse() {
    let result: Result<serde_json::Value, _> = serde_json::from_str("not json");
    assert!(result.is_err(), "malformed JSON must fail to parse");
    if let Err(serde_err) = result {
        assert_eq!(JcsError::from(serde_err).code(), "json-parse");
    }
}

#[test]
fn duplicate_key_variant_code_is_duplicate_key() {
    let err = JcsError::DuplicateKey("duplicate property name `x`".to_string());
    assert_eq!(err.code(), "duplicate-key");
}

#[test]
fn invalid_string_variant_code_is_i_json_string() {
    let err = JcsError::InvalidString("noncharacter U+FDD0".to_string());
    assert_eq!(err.code(), "i-json-string");
}

#[test]
fn invalid_number_variant_code_is_i_json_number() {
    let err = JcsError::InvalidNumber("non-exact integer".to_string());
    assert_eq!(err.code(), "i-json-number");
}

#[test]
fn nesting_depth_exceeded_variant_code_is_nesting_depth() {
    assert_eq!(JcsError::NestingDepthExceeded.code(), "nesting-depth");
}

#[test]
fn unsupported_algorithm_variant_code_is_unsupported_algorithm() {
    let err = JcsError::UnsupportedAlgorithm("sha256 not wired".to_string());
    assert_eq!(err.code(), "unsupported-algorithm");
}
