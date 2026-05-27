//! ADR-002 Ratification Criterion C2 — `CanonicalDigest::algorithm`
//! carries the exact `DigestAlgorithm` that the input `DigestStrategy`
//! held, for every wired mode.
//!
//! This proves the **algorithm-with-output binding** invariant from
//! ADR-002 § Decision item 3: the algorithm travels with the bytes so
//! downstream receipt envelopes do not have to track the algorithm
//! choice out-of-band.
//!
//! Coverage: the three wired BLAKE3 modes. `Sha256` is excluded because
//! the call errors at the algorithm dispatch (covered by C4); no
//! `CanonicalDigest` is produced.
//!
//! Algorithm-payload data (the 32-byte key, the context string) must
//! also round-trip verbatim — a regression that dropped the key or
//! context from the output `DigestAlgorithm` would break receipt
//! auditability.

use vr_jcs::{to_canon_digest_with, DigestStrategy, JcsError};

#[test]
fn canonical_digest_carries_blake3_untagged_algorithm() -> Result<(), JcsError> {
    let strategy = DigestStrategy::blake3_untagged();
    let expected_algorithm = strategy.algorithm.clone();

    let value = serde_json::json!({"x": 1});
    let digest = to_canon_digest_with(&value, &strategy)?;

    assert_eq!(
        digest.algorithm, expected_algorithm,
        "CanonicalDigest must carry Blake3Untagged verbatim",
    );
    Ok(())
}

#[test]
fn canonical_digest_carries_blake3_keyed_algorithm_with_same_key() -> Result<(), JcsError> {
    let key: [u8; 32] = [0x12; 32];
    let strategy = DigestStrategy::blake3_keyed(key);
    let expected_algorithm = strategy.algorithm.clone();

    let value = serde_json::json!({"x": 1});
    let digest = to_canon_digest_with(&value, &strategy)?;

    assert_eq!(
        digest.algorithm, expected_algorithm,
        "CanonicalDigest must carry Blake3Keyed with the original 32-byte key",
    );
    Ok(())
}

#[test]
fn canonical_digest_carries_blake3_domain_separated_algorithm_with_same_context(
) -> Result<(), JcsError> {
    let context = "vr-jcs ADR-002 C2 passthrough context";
    let strategy = DigestStrategy::blake3_domain_separated(context);
    let expected_algorithm = strategy.algorithm.clone();

    let value = serde_json::json!({"x": 1});
    let digest = to_canon_digest_with(&value, &strategy)?;

    assert_eq!(
        digest.algorithm, expected_algorithm,
        "CanonicalDigest must carry Blake3DomainSeparated with the original context",
    );
    Ok(())
}
