//! ADR-002 Ratification Criterion C6 — `DigestAlgorithm::name()` returns
//! the four bound algorithm-name strings verbatim.
//!
//! The names appear in receipt schemas and audit trails as the
//! canonical algorithm identifiers. Renaming any one is a breaking
//! change per ADR-002 § Compatibility Guarantees.
//!
//! This test pins the names for the four currently-wired-or-reserved
//! variants. New variants admitted under `#[non_exhaustive]` will not
//! cause this test to fail; the test asserts only that the four named
//! variants retain their bound name strings.
//!
//! Construction routes through `DigestStrategy` constructors to align
//! with ADR-002 § Decision item 2 (constructor-only discipline).

use vr_jcs::DigestStrategy;

#[test]
fn blake3_untagged_name_is_pinned() {
    assert_eq!(
        DigestStrategy::blake3_untagged().algorithm.name(),
        "blake3-untagged",
    );
}

#[test]
fn blake3_keyed_name_is_pinned() {
    assert_eq!(
        DigestStrategy::blake3_keyed([0u8; 32]).algorithm.name(),
        "blake3-keyed",
    );
}

#[test]
fn blake3_domain_separated_name_is_pinned() {
    assert_eq!(
        DigestStrategy::blake3_domain_separated("test-context")
            .algorithm
            .name(),
        "blake3-domain-separated",
    );
}

#[test]
fn sha256_name_is_pinned() {
    assert_eq!(DigestStrategy::sha256().algorithm.name(), "sha256");
}
