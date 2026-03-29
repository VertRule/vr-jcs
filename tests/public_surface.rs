//! Public surface regression test for vr-jcs v0.1.
//!
//! Asserts that the blessed public API symbols compile and are usable.
//! Review against `PUBLIC_SURFACE.md` when preparing releases.

#![deny(unused_imports)]

use vr_jcs::canonicalize;
use vr_jcs::to_canon_bytes;
use vr_jcs::to_canon_bytes_from_slice;
use vr_jcs::to_canon_string;
use vr_jcs::to_canon_string_from_str;
use vr_jcs::JcsError;

#[test]
fn public_surface_symbols_are_usable() -> Result<(), JcsError> {
    // to_canon_bytes
    let bytes = to_canon_bytes(&serde_json::json!({"a": 1}))?;
    assert!(!bytes.is_empty());

    // to_canon_string
    let s = to_canon_string(&serde_json::json!({"b": 2}))?;
    assert_eq!(s, r#"{"b":2}"#);

    // to_canon_bytes_from_slice
    let from_slice = to_canon_bytes_from_slice(br#"{"c": 3}"#)?;
    assert!(!from_slice.is_empty());

    // to_canon_string_from_str
    let from_str = to_canon_string_from_str(r#"{"d": 4}"#)?;
    assert_eq!(from_str, r#"{"d":4}"#);

    // canonicalize (in-place)
    let mut val = serde_json::json!({"z": 1, "a": 2});
    canonicalize(&mut val);

    Ok(())
}
