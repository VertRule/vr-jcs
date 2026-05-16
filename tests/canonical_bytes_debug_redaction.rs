//! ADR-001 Ratification Criterion #6 — `CanonicalBytes::Debug` prints
//! length only and never leaks the underlying bytes.
//!
//! The receipt-leak hazard: a `Debug` impl that prints the contents of
//! `CanonicalBytes` would dump raw canonical JSON into any `tracing` /
//! `eprintln!` / panic message that happens to format the value. ADR-001
//! Security Considerations binds the length-only Debug invariant as the
//! mitigation.
//!
//! Tests prove three properties of `{canon:?}`:
//!
//! 1. The byte length appears in the formatted output.
//! 2. A sentinel string value embedded in the input does NOT appear in
//!    the formatted output (proves value redaction).
//! 3. A sentinel property name embedded in the input does NOT appear in
//!    the formatted output (proves key redaction).
//!
//! Each test returns `Result<(), vr_jcs::JcsError>` so the canonical-bytes
//! construction is propagated with `?` rather than `unwrap`/`expect`.

use vr_jcs::{canonical_bytes_from_slice, JcsError};

#[test]
fn debug_output_contains_byte_length() -> Result<(), JcsError> {
    let canon = canonical_bytes_from_slice(br#"{"k":"v"}"#)?;
    let debug_str = format!("{canon:?}");
    let len_str = canon.len().to_string();

    assert!(
        debug_str.contains("len"),
        "Debug must announce a `len` field — got {debug_str}",
    );
    assert!(
        debug_str.contains(&len_str),
        "Debug must include the byte length {len_str} — got {debug_str}",
    );
    Ok(())
}

#[test]
fn debug_output_does_not_leak_string_value_bytes() -> Result<(), JcsError> {
    let sentinel = "DO_NOT_LOG_SENTINEL_VALUE_a8f3";
    let input = format!(r#"{{"k":"{sentinel}"}}"#);

    let canon = canonical_bytes_from_slice(input.as_bytes())?;
    let debug_str = format!("{canon:?}");

    assert!(
        !debug_str.contains(sentinel),
        "Debug must NOT leak string-value bytes ({sentinel} found in {debug_str})",
    );
    Ok(())
}

#[test]
fn debug_output_does_not_leak_property_name_bytes() -> Result<(), JcsError> {
    let sentinel = "DO_NOT_LOG_SENTINEL_KEY_b9c1";
    let input = format!(r#"{{"{sentinel}":1}}"#);

    let canon = canonical_bytes_from_slice(input.as_bytes())?;
    let debug_str = format!("{canon:?}");

    assert!(
        !debug_str.contains(sentinel),
        "Debug must NOT leak property-name bytes ({sentinel} found in {debug_str})",
    );
    Ok(())
}

#[test]
fn debug_output_size_is_independent_of_payload_size() -> Result<(), JcsError> {
    // The Debug impl prints only a small length number; a payload that
    // is much larger than the Debug-output budget guards against a
    // regression where someone adds the bytes to Debug "for convenience".
    let large_value = "z".repeat(8192);
    let input = format!(r#"{{"k":"{large_value}"}}"#);

    let canon = canonical_bytes_from_slice(input.as_bytes())?;
    let debug_str = format!("{canon:?}");

    assert!(
        debug_str.len() < 128,
        "Debug output must remain compact regardless of payload size; \
         got {} bytes for an 8 KiB payload — possible byte leak",
        debug_str.len(),
    );
    Ok(())
}
