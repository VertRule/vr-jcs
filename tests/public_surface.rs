//! Public surface regression test for vr-jcs v0.3.
//!
//! Asserts that the blessed public API symbols compile and are usable.
//! Review against `PUBLIC_SURFACE.md` when preparing releases.

#![deny(unused_imports)]

use vr_jcs::canonicalize;
use vr_jcs::to_canon_bytes_from_slice;
use vr_jcs::to_canon_string_from_str;
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
