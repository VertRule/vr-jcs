//! ADR-002 Ratification Criterion C1 — BLAKE3 digest modes byte-match
//! the BLAKE3-spec primitives.
//!
//! Each wired BLAKE3 mode in `DigestAlgorithm` must produce a digest
//! byte-for-byte identical to the `blake3` crate's spec primitive when
//! applied to the same canonical input:
//!
//! - `Blake3Untagged` ≡ `blake3::hash(canonical_bytes)`
//! - `Blake3Keyed { key }` ≡ `blake3::keyed_hash(&key, canonical_bytes)`
//! - `Blake3DomainSeparated { context }` ≡ `blake3::derive_key(context, canonical_bytes)`
//!
//! Canonical bytes come from the strict path
//! (`canonical_bytes_from_slice`), which routes through the same
//! `to_canon_bytes_value` emit pipeline used by `to_canon_digest_with`.

use vr_jcs::{
    canonical_bytes_from_slice, to_canon_digest_with, DigestStrategy, JcsError,
};

const REPRESENTATIVE_INPUT: &[u8] =
    br#"{"alpha":1,"nested":{"beta":2,"gamma":[3,4]}}"#;

fn canonical_value_and_bytes() -> Result<(serde_json::Value, Vec<u8>), JcsError> {
    let canonical = canonical_bytes_from_slice(REPRESENTATIVE_INPUT)?;
    let value: serde_json::Value =
        serde_json::from_slice(canonical.as_slice()).map_err(JcsError::from)?;
    Ok((value, canonical.into_vec()))
}

#[test]
fn blake3_untagged_byte_matches_blake3_hash() -> Result<(), JcsError> {
    let (value, canonical) = canonical_value_and_bytes()?;

    let via_strategy =
        to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    let direct = blake3::hash(&canonical);

    assert_eq!(
        via_strategy.bytes.as_slice(),
        direct.as_bytes(),
        "Blake3Untagged must equal blake3::hash on canonical bytes",
    );
    Ok(())
}

#[test]
fn blake3_keyed_byte_matches_blake3_keyed_hash() -> Result<(), JcsError> {
    let (value, canonical) = canonical_value_and_bytes()?;
    let key: [u8; 32] = [0xAB; 32];

    let via_strategy =
        to_canon_digest_with(&value, &DigestStrategy::blake3_keyed(key))?;
    let direct = blake3::keyed_hash(&key, &canonical);

    assert_eq!(
        via_strategy.bytes.as_slice(),
        direct.as_bytes(),
        "Blake3Keyed must equal blake3::keyed_hash on canonical bytes",
    );
    Ok(())
}

#[test]
fn blake3_domain_separated_byte_matches_blake3_derive_key() -> Result<(), JcsError> {
    let (value, canonical) = canonical_value_and_bytes()?;
    let context = "vr-jcs ADR-002 ratification C1 conformance v1";

    let via_strategy = to_canon_digest_with(
        &value,
        &DigestStrategy::blake3_domain_separated(context),
    )?;
    let direct = blake3::derive_key(context, &canonical);

    assert_eq!(
        via_strategy.bytes.as_slice(),
        &direct[..],
        "Blake3DomainSeparated must equal blake3::derive_key on canonical bytes",
    );
    Ok(())
}
