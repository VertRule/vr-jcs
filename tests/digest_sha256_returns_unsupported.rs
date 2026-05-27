//! ADR-002 Ratification Criterion C4 — `to_canon_digest_with` with the
//! SHA-256 strategy returns `JcsError::UnsupportedAlgorithm` at call
//! time and carries a useful diagnostic message.
//!
//! Per ADR-002 § Decision item 5, `Sha256` is a forward reservation:
//! the variant exists so receipt schemas and policy packs may reference
//! the algorithm before it is wired. Until a future wiring lands, every
//! strategy-bearing call routing through `Sha256` must error at call
//! time — never silently succeed under a different algorithm.

use vr_jcs::{to_canon_digest_with, DigestStrategy, JcsError};

#[test]
fn sha256_strategy_returns_unsupported_algorithm_variant() {
    let value = serde_json::json!({"x": 1});
    let result = to_canon_digest_with(&value, &DigestStrategy::sha256());

    assert!(
        matches!(&result, Err(JcsError::UnsupportedAlgorithm(_))),
        "SHA-256 strategy must return Err(JcsError::UnsupportedAlgorithm(_)); \
         got {result:?}",
    );
}

#[test]
fn sha256_unsupported_algorithm_message_identifies_algorithm() {
    let value = serde_json::json!({"x": 1});
    let result = to_canon_digest_with(&value, &DigestStrategy::sha256());

    if let Err(JcsError::UnsupportedAlgorithm(msg)) = result {
        assert!(
            !msg.is_empty(),
            "UnsupportedAlgorithm message must be non-empty",
        );
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("sha") || lower.contains("256"),
            "UnsupportedAlgorithm message must identify the unsupported \
             algorithm (mentions 'sha' or '256'); got {msg:?}",
        );
    } else {
        // Sibling test asserts the variant; if we reach here in isolation
        // it means SHA-256 silently succeeded — surface that explicitly.
        let result_again = to_canon_digest_with(&value, &DigestStrategy::sha256());
        assert!(
            matches!(&result_again, Err(JcsError::UnsupportedAlgorithm(_))),
            "SHA-256 strategy must return UnsupportedAlgorithm; \
             this test cannot reach the message assertion",
        );
    }
}
