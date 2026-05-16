//! ADR-001 Ratification Criterion #8 — public-API symbols bound by
//! ADR-001 § Public API / Contract compile against the published surface.
//!
//! Each symbol named in the ADR is invoked at its bound signature with
//! explicit `let _: T = ...;` type annotations that pin the return type
//! or the field type. A rename, removal, or breaking signature change
//! makes this file fail to compile under `-D warnings`, surfacing the
//! drift in CI before a release ships.
//!
//! Sibling `tests/public_surface.rs` covers the same surface from a
//! release-regression angle; this file exists as the ADR-001-bound
//! ratification artifact and may differ from it as the ADR evolves
//! independently of release-history concerns.

#![deny(unused_imports)]

use vr_jcs::{
    canonical_bytes_from_slice, canonicalize, strict_parse, to_canon_blake3_digest,
    to_canon_blake3_digest_from_slice, to_canon_bytes_from_slice, to_canon_digest_with,
    to_canon_string_from_str, CanonicalBytes, CanonicalDigest, DigestAlgorithm,
    DigestStrategy, JcsError, JcsErrorInfo, MAX_NESTING_DEPTH,
};

#[test]
fn max_nesting_depth_is_typed_usize_and_equals_128() {
    let depth: usize = MAX_NESTING_DEPTH;
    assert_eq!(depth, 128);
}

#[test]
fn strict_path_signatures_compile() -> Result<(), JcsError> {
    let bytes: Vec<u8> = to_canon_bytes_from_slice(br#"{"x":1}"#)?;
    assert!(!bytes.is_empty());

    let string: String = to_canon_string_from_str(r#"{"x":1}"#)?;
    assert_eq!(string, r#"{"x":1}"#);

    let canon: CanonicalBytes = canonical_bytes_from_slice(br#"{"x":1}"#)?;
    let _slice: &[u8] = canon.as_slice();
    let _len: usize = canon.len();
    let _empty: bool = canon.is_empty();
    let _owned: Vec<u8> = canon.into_vec();

    Ok(())
}

#[test]
fn in_place_canonicalize_signature_compiles() -> Result<(), JcsError> {
    let mut value = serde_json::json!({"z": 1, "a": 2});
    canonicalize(&mut value)?;
    Ok(())
}

#[allow(deprecated)]
#[test]
fn deprecated_typed_path_signatures_compile() -> Result<(), JcsError> {
    let value = serde_json::json!({"x": 1});
    let _bytes: Vec<u8> = vr_jcs::to_canon_bytes(&value)?;
    let _string: String = vr_jcs::to_canon_string(&value)?;
    Ok(())
}

#[test]
fn digest_api_signatures_compile() -> Result<(), JcsError> {
    let value = serde_json::json!({"x": 1});

    let _untagged: DigestStrategy = DigestStrategy::blake3_untagged();
    let _keyed: DigestStrategy = DigestStrategy::blake3_keyed([0u8; 32]);
    let _domain: DigestStrategy = DigestStrategy::blake3_domain_separated("ctx");
    let _sha: DigestStrategy = DigestStrategy::sha256();

    let digest: CanonicalDigest =
        to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    let _name: &'static str = digest.algorithm.name();
    let _len: usize = digest.bytes.len();

    let _from_value: [u8; 32] = to_canon_blake3_digest(&value)?;
    let _from_slice: [u8; 32] = to_canon_blake3_digest_from_slice(br#"{"x":1}"#)?;

    Ok(())
}

#[test]
fn digest_algorithm_variants_construct_via_strategy() -> Result<(), JcsError> {
    // ADR-001 binds DigestAlgorithm as `#[non_exhaustive]` with named
    // variants. Construction via DigestStrategy keeps callers from
    // matching on the enum directly.
    let strategies = [
        DigestStrategy::blake3_untagged(),
        DigestStrategy::blake3_keyed([0u8; 32]),
        DigestStrategy::blake3_domain_separated("ctx"),
    ];
    let value = serde_json::json!({"x": 1});
    for strategy in &strategies {
        let digest = to_canon_digest_with(&value, strategy)?;
        let _: &DigestAlgorithm = &digest.algorithm;
        assert_eq!(digest.bytes.len(), 32);
    }
    Ok(())
}

#[test]
fn error_projection_signatures_compile() {
    let result = to_canon_bytes_from_slice(b"not json at all");
    assert!(
        result.is_err(),
        "strict path must reject malformed input for this signature check",
    );
    if let Err(err) = result {
        // JcsError::into_info projects into the stable JcsErrorInfo enum.
        let info: JcsErrorInfo = err.into_info();
        // JcsErrorInfo is exhaustively matchable (ADR-001 § Compatibility).
        match info {
            JcsErrorInfo::Json(_) | JcsErrorInfo::Validation(_) => {}
        }
    }
}

#[test]
fn strict_parse_module_signatures_compile() -> Result<(), JcsError> {
    let _: i64 = strict_parse::MAX_SAFE_INTEGER;

    let _value: serde_json::Value =
        strict_parse::parse_json_value_no_duplicates(br#"{"x":1}"#)?;

    let mut deserializer = serde_json::Deserializer::from_slice(br#"{"x":1}"#);
    let _via_de: serde_json::Value =
        strict_parse::deserialize_json_value_no_duplicates(&mut deserializer)
            .map_err(JcsError::from)?;

    let _validation: Result<(), String> = strict_parse::validate_string_contents("ok", "ctx");
    let _safe: bool = strict_parse::is_safe_integer(42);

    Ok(())
}
