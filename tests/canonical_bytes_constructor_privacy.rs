//! ADR-001 Ratification Criterion #10 — external callers cannot forge
//! `CanonicalBytes`; only `canonical_bytes_from_slice` constructs the
//! type.
//!
//! The **negative** half of this criterion — that
//! `CanonicalBytes::from_jcs` is unreachable from external code — is
//! proved by a `compile_fail` doctest attached to the `CanonicalBytes`
//! struct in `src/canonical_bytes.rs`. That doctest must fail to compile
//! whenever `cargo test --doc` runs; if `from_jcs` were ever raised to
//! `pub`, the doctest would compile and the test would fail.
//!
//! This file is the **positive** half: it asserts that the legitimate
//! public path is reachable, that the returned value behaves as a
//! `CanonicalBytes`, and that ownership transfer via `into_vec` works.
//! Together the two artifacts pin the boundary in both directions.
//!
//! The doctest is the load-bearing compile-fail proof — see
//! `src/canonical_bytes.rs`. Do not delete it without an ADR amendment.

use vr_jcs::{canonical_bytes_from_slice, CanonicalBytes, JcsError};

#[test]
fn legitimate_public_path_constructs_canonical_bytes() -> Result<(), JcsError> {
    let canon: CanonicalBytes = canonical_bytes_from_slice(br#"{"k":"v"}"#)?;
    assert!(!canon.is_empty());
    assert_eq!(canon.len(), canon.as_slice().len());
    Ok(())
}

#[test]
fn canonical_bytes_round_trips_via_into_vec() -> Result<(), JcsError> {
    let canon = canonical_bytes_from_slice(br#"{"a":1,"b":2}"#)?;
    let expected = b"{\"a\":1,\"b\":2}";
    assert_eq!(canon.as_slice(), expected);

    let owned: Vec<u8> = canon.into_vec();
    assert_eq!(owned, expected);
    Ok(())
}

#[test]
fn distinct_inputs_yield_distinct_canonical_bytes() -> Result<(), JcsError> {
    let a = canonical_bytes_from_slice(br#"{"x":1}"#)?;
    let b = canonical_bytes_from_slice(br#"{"x":2}"#)?;
    assert_ne!(a.as_slice(), b.as_slice());
    Ok(())
}

#[test]
fn key_order_normalized_via_canonical_bytes_path() -> Result<(), JcsError> {
    // Two inputs that differ only in key order must produce equal
    // CanonicalBytes — the type carries "post-canonicalization" as a
    // type-level fact.
    let a = canonical_bytes_from_slice(br#"{"a":1,"b":2}"#)?;
    let b = canonical_bytes_from_slice(br#"{"b":2,"a":1}"#)?;
    assert_eq!(a.as_slice(), b.as_slice());
    Ok(())
}
