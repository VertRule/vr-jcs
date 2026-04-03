//! Fixture-based compatibility tests.
//!
//! Frozen real receipts from the `VertRule` governance ecosystem,
//! proving that `MAX_NESTING_DEPTH = 128` does not reject any
//! existing artifact shape.

/// Canonical governance guard receipt (5 levels, from governance/.vr/receipts/).
const CANONICAL_RECEIPT: &[u8] = include_bytes!("fixtures/canonical_governance_receipt.json");

/// Pretty-printed capability discovery receipt (non-canonical whitespace).
const PRETTY_RECEIPT: &[u8] = include_bytes!("fixtures/pretty_printed_receipt.json");

/// Minimal canonical payload (4 levels).
const CANONICAL_PAYLOAD: &[u8] = include_bytes!("fixtures/canonical_payload_min.json");

// ── Strict parse + canonical emit ────────────────────────────────

#[test]
fn canonical_receipt_accepted_strict() -> Result<(), vr_jcs::JcsError> {
    let bytes = vr_jcs::to_canon_bytes_from_slice(CANONICAL_RECEIPT)?;
    assert!(!bytes.is_empty());
    // Canonical input round-trips to itself
    assert_eq!(bytes, CANONICAL_RECEIPT);
    Ok(())
}

#[test]
fn canonical_payload_accepted_strict() -> Result<(), vr_jcs::JcsError> {
    let bytes = vr_jcs::to_canon_bytes_from_slice(CANONICAL_PAYLOAD)?;
    assert_eq!(bytes, CANONICAL_PAYLOAD);
    Ok(())
}

#[test]
fn pretty_receipt_accepted_via_serde_roundtrip() -> Result<(), vr_jcs::JcsError> {
    // Roundtrip through serde_json (strips whitespace) then strict parse.
    let value: serde_json::Value =
        serde_json::from_slice(PRETTY_RECEIPT).map_err(vr_jcs::JcsError::from)?;
    let text = serde_json::to_string(&value).map_err(vr_jcs::JcsError::from)?;
    let bytes = vr_jcs::to_canon_bytes_from_slice(text.as_bytes())?;
    assert!(!bytes.is_empty());
    Ok(())
}

#[test]
fn pretty_receipt_strict_parse_and_canonical_emit() -> Result<(), vr_jcs::JcsError> {
    // Admitted noncanonical input: pretty-printed JSON with whitespace.
    // Strict parse + canonical emit accepts it and produces canonical output.
    let bytes = vr_jcs::to_canon_bytes_from_slice(PRETTY_RECEIPT)?;
    assert!(!bytes.is_empty());
    // Output is canonicalized: differs from pretty input bytes
    assert_ne!(bytes.as_slice(), PRETTY_RECEIPT);
    Ok(())
}

// ── Digest stability ─────────────────────────────────────────────

#[test]
fn canonical_receipt_digest_is_stable() -> Result<(), vr_jcs::JcsError> {
    let bytes = vr_jcs::to_canon_bytes_from_slice(CANONICAL_RECEIPT)?;
    let digest = blake3::hash(&bytes);
    // Frozen golden value — if this changes, canonical output changed.
    assert_eq!(
        digest.to_hex().as_str(),
        "5c2064323dbec6efbdd9d2c96b016b87626b4ec829e4c64643f7770c64396716",
        "canonical receipt digest changed — canonicalization output is unstable"
    );
    Ok(())
}
