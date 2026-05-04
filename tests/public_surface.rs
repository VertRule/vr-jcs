//! Public surface regression test for vr-jcs v0.3.
//!
//! Asserts that the blessed public API symbols compile and are usable.
//! Review against `PUBLIC_SURFACE.md` when preparing releases.

#![deny(unused_imports)]

use vr_jcs::canonical_bytes_from_slice;
use vr_jcs::canonicalize;
use vr_jcs::to_canon_bytes_from_slice;
use vr_jcs::to_canon_string_from_str;
use vr_jcs::CanonicalBytes;
use vr_jcs::CanonicalDigest;
use vr_jcs::DigestAlgorithm;
use vr_jcs::DigestStrategy;
use vr_jcs::JcsError;

#[test]
fn strict_path_symbols_are_usable() -> Result<(), JcsError> {
    let from_slice = to_canon_bytes_from_slice(br#"{"c": 3}"#)?;
    assert!(!from_slice.is_empty());

    let from_str = to_canon_string_from_str(r#"{"d": 4}"#)?;
    assert_eq!(from_str, r#"{"d":4}"#);

    let mut val = serde_json::json!({"z": 1, "a": 2});
    canonicalize(&mut val)?;

    assert_eq!(vr_jcs::MAX_NESTING_DEPTH, 128);

    Ok(())
}

#[allow(deprecated)]
#[test]
fn deprecated_typed_path_symbols_are_usable() -> Result<(), JcsError> {
    use vr_jcs::to_canon_bytes;
    use vr_jcs::to_canon_string;

    let bytes = to_canon_bytes(&serde_json::json!({"a": 1}))?;
    assert!(!bytes.is_empty());

    let s = to_canon_string(&serde_json::json!({"b": 2}))?;
    assert_eq!(s, r#"{"b":2}"#);

    Ok(())
}

#[test]
fn digest_strategy_symbols_are_usable() -> Result<(), JcsError> {
    // Lock in the strategy-bearing digest API so a symbol rename or
    // visibility tightening is caught at the public boundary.
    use vr_jcs::to_canon_digest_with;

    let value = serde_json::json!({"x": 1});

    let plain = to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    assert_eq!(plain.algorithm, DigestAlgorithm::Blake3Untagged);
    assert_eq!(plain.bytes.len(), 32);
    assert_eq!(plain.algorithm.name(), "blake3-untagged");

    let keyed = to_canon_digest_with(&value, &DigestStrategy::blake3_keyed([0u8; 32]))?;
    assert_ne!(keyed.bytes, plain.bytes, "keyed must differ from plain");

    let domain = to_canon_digest_with(&value, &DigestStrategy::blake3_domain_separated("test"))?;
    assert_eq!(domain.algorithm.name(), "blake3-domain-separated");

    // SHA-256 variant is declared but unimplemented; constructor must be
    // callable so policy code can reference it today.
    let sha = DigestStrategy::sha256();
    let err = to_canon_digest_with(&value, &sha);
    assert!(
        matches!(err, Err(JcsError::UnsupportedAlgorithm(_))),
        "expected UnsupportedAlgorithm, got {err:?}"
    );

    // Typed-output accessor reachability.
    let _: &[u8] = &plain.bytes;
    let _: &DigestAlgorithm = &plain.algorithm;
    let _: CanonicalDigest = plain;

    Ok(())
}

#[test]
fn fixed_blake3_convenience_symbols_are_usable() -> Result<(), JcsError> {
    // Lock in the fixed-BLAKE3 convenience wrappers.
    use vr_jcs::to_canon_blake3_digest;
    use vr_jcs::to_canon_blake3_digest_from_slice;

    let from_value = to_canon_blake3_digest(&serde_json::json!({"a": 1}))?;
    assert_eq!(from_value.len(), 32);

    let from_slice = to_canon_blake3_digest_from_slice(br#"{"a":1}"#)?;
    assert_eq!(from_value, from_slice);

    Ok(())
}

#[test]
fn canonical_bytes_newtype_wraps_and_matches_raw_path() -> Result<(), JcsError> {
    let raw = to_canon_bytes_from_slice(br#"{"b":2,"a":1}"#)?;
    let wrapped: CanonicalBytes = canonical_bytes_from_slice(br#"{"b":2,"a":1}"#)?;

    assert_eq!(wrapped.as_slice(), raw.as_slice());
    assert_eq!(wrapped.len(), raw.len());
    assert!(!wrapped.is_empty());

    // Debug must not leak the bytes themselves.
    let debug_repr = format!("{wrapped:?}");
    assert!(
        debug_repr.contains("CanonicalBytes") && debug_repr.contains("len"),
        "unexpected Debug shape: {debug_repr}"
    );
    assert!(
        !debug_repr.contains(r#""a":1"#),
        "Debug must not include bytes: {debug_repr}"
    );

    // into_vec gives ownership back; equal to the raw path.
    let recovered = wrapped.into_vec();
    assert_eq!(recovered, raw);

    Ok(())
}
