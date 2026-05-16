//! ADR-003 Ratification Criterion C3 — no two `JcsError` variants
//! share a code string; the registry forms a bijection between variants
//! and codes.
//!
//! C1 pins each variant to a specific code string. C3 catches the
//! complementary failure mode: a refactor where two variants
//! accidentally produce the same code (and the C1 expectations were
//! adjusted in lockstep). The bijection is enforced by building one
//! instance per variant, collecting codes into a `BTreeSet`, and
//! asserting cardinality equals the variant count.

use std::collections::BTreeSet;

use vr_jcs::JcsError;

fn make_json_error_variant() -> Option<JcsError> {
    let result: Result<serde_json::Value, _> = serde_json::from_str("not json");
    result.err().map(JcsError::from)
}

#[test]
fn variant_to_code_mapping_is_injective() {
    let json = make_json_error_variant();
    assert!(
        json.is_some(),
        "serde_json must reject `not json`; required to construct the Json variant",
    );
    let Some(json) = json else {
        return;
    };

    let variants = [
        json,
        JcsError::DuplicateKey("dup".to_string()),
        JcsError::InvalidString("s".to_string()),
        JcsError::InvalidNumber("n".to_string()),
        JcsError::NestingDepthExceeded,
        JcsError::UnsupportedAlgorithm("u".to_string()),
    ];

    let expected_count = variants.len();
    let codes: BTreeSet<&'static str> = variants.iter().map(JcsError::code).collect();

    assert_eq!(
        codes.len(),
        expected_count,
        "Code mapping must be injective ({expected_count} distinct variants \
         → {expected_count} distinct codes); got {codes:?}",
    );
}
