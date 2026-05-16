//! ADR-002 Ratification Criterion C3 — different digest modes on the
//! same canonical input produce distinct bytes.
//!
//! Four pairwise comparisons pin BLAKE3 mode separation:
//!
//! 1. `Blake3Untagged` vs. `Blake3Keyed` — keying changes the digest
//!    even for an otherwise-identical canonical input.
//! 2. `Blake3Untagged` vs. `Blake3DomainSeparated` — domain separation
//!    changes the digest.
//! 3. `Blake3Keyed { key: A }` vs. `Blake3Keyed { key: B }` — different
//!    keys produce different digests (no key reuse cross-contamination).
//! 4. `Blake3DomainSeparated { context: A }` vs.
//!    `Blake3DomainSeparated { context: B }` — different contexts
//!    produce different digests (per-domain separation).
//!
//! Each pair asserts byte-inequality (`assert_ne!`). A coincidental
//! BLAKE3 collision would be vanishingly unlikely (~2^-256); a failure
//! here means a wiring regression (e.g. one mode silently routing to
//! the other), not a cryptographic collision.

use vr_jcs::{to_canon_digest_with, DigestStrategy, JcsError};

const SHARED_INPUT_JSON: &str = r#"{"alpha":1,"beta":2}"#;

fn digest_under_strategy(strategy: DigestStrategy) -> Result<Vec<u8>, JcsError> {
    let value: serde_json::Value =
        serde_json::from_str(SHARED_INPUT_JSON).map_err(JcsError::from)?;
    let digest = to_canon_digest_with(&value, &strategy)?;
    Ok(digest.bytes)
}

#[test]
fn untagged_and_keyed_yield_distinct_bytes() -> Result<(), JcsError> {
    let untagged = digest_under_strategy(DigestStrategy::blake3_untagged())?;
    let keyed = digest_under_strategy(DigestStrategy::blake3_keyed([0x01; 32]))?;
    assert_ne!(
        untagged, keyed,
        "Blake3Untagged and Blake3Keyed must produce distinct digests \
         on the same canonical input",
    );
    Ok(())
}

#[test]
fn untagged_and_domain_separated_yield_distinct_bytes() -> Result<(), JcsError> {
    let untagged = digest_under_strategy(DigestStrategy::blake3_untagged())?;
    let domain = digest_under_strategy(
        DigestStrategy::blake3_domain_separated("vr-jcs ADR-002 C3 context"),
    )?;
    assert_ne!(
        untagged, domain,
        "Blake3Untagged and Blake3DomainSeparated must produce distinct \
         digests on the same canonical input",
    );
    Ok(())
}

#[test]
fn keyed_with_different_keys_yield_distinct_bytes() -> Result<(), JcsError> {
    let key_a: [u8; 32] = [0x11; 32];
    let key_b: [u8; 32] = [0x22; 32];
    let a = digest_under_strategy(DigestStrategy::blake3_keyed(key_a))?;
    let b = digest_under_strategy(DigestStrategy::blake3_keyed(key_b))?;
    assert_ne!(
        a, b,
        "Blake3Keyed with distinct keys must produce distinct digests",
    );
    Ok(())
}

#[test]
fn domain_separated_with_different_contexts_yield_distinct_bytes()
-> Result<(), JcsError> {
    let context_a = "vr-jcs ADR-002 C3 context A";
    let context_b = "vr-jcs ADR-002 C3 context B";
    let a = digest_under_strategy(DigestStrategy::blake3_domain_separated(context_a))?;
    let b = digest_under_strategy(DigestStrategy::blake3_domain_separated(context_b))?;
    assert_ne!(
        a, b,
        "Blake3DomainSeparated with distinct contexts must produce \
         distinct digests",
    );
    Ok(())
}
