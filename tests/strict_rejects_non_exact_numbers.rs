//! ADR-001 Ratification Criterion #3 — strict path rejects JSON numbers
//! that are not admissible under the JCS number contract.
//!
//! Proves differential admission across every strict-path entry point,
//! including `strict_parse::parse_json_value_no_duplicates` which the
//! ADR-001 ratification work hardened to enforce number admission on
//! parse (previously only the byte-emit pipeline enforced it).
//!
//! Coverage is structural:
//!
//! - positive integer one above the I-JSON safe-integer ceiling
//!   (`2^53 + 1` = `9_007_199_254_740_993`),
//! - negative integer one below the I-JSON safe-integer floor,
//! - positive exponential that parses as `+Infinity` under IEEE 754
//!   (`1e500`),
//! - negative exponential that parses as `-Infinity`,
//! - the same positive non-exact integer nested inside an object
//!   (proves the post-parse walk traverses objects),
//! - the same value inside an array (proves traversal of array elements).
//!
//! Positive controls use the I-JSON safe-integer ceiling
//! (`2^53 - 1` = `9_007_199_254_740_991`) and finite, exactly-representable
//! floats. The boundary integer `2^53` (`9_007_199_254_740_992`) is
//! **admitted** by the existing predicate via the trailing-zeros rule in
//! `is_exact_binary64_integer`; tests avoid that boundary to stay clear
//! of the predicate's edge.
//!
//! ADR-001 binds the admission *predicate*, not the error taxonomy; the
//! helper inspects only `is_err()` / `is_ok()`. Stable machine-readable
//! error projection is the obligation of ADR-003.

use vr_jcs::{
    canonical_bytes_from_slice, strict_parse, to_canon_bytes_from_slice, to_canon_string_from_str,
};

#[derive(Clone, Copy)]
enum StrictEntryPoint {
    CanonBytesFromSlice,
    CanonStringFromStr,
    CanonicalBytesFromSlice,
    StrictParseNoDuplicates,
}

impl StrictEntryPoint {
    const fn name(self) -> &'static str {
        match self {
            Self::CanonBytesFromSlice => "to_canon_bytes_from_slice",
            Self::CanonStringFromStr => "to_canon_string_from_str",
            Self::CanonicalBytesFromSlice => "canonical_bytes_from_slice",
            Self::StrictParseNoDuplicates => "strict_parse::parse_json_value_no_duplicates",
        }
    }

    fn admits(self, json: &[u8]) -> bool {
        match self {
            Self::CanonBytesFromSlice => to_canon_bytes_from_slice(json).is_ok(),
            Self::CanonStringFromStr => match std::str::from_utf8(json) {
                Ok(text) => to_canon_string_from_str(text).is_ok(),
                Err(_) => false,
            },
            Self::CanonicalBytesFromSlice => canonical_bytes_from_slice(json).is_ok(),
            Self::StrictParseNoDuplicates => {
                strict_parse::parse_json_value_no_duplicates(json).is_ok()
            }
        }
    }
}

const ALL_ENTRY_POINTS: [StrictEntryPoint; 4] = [
    StrictEntryPoint::CanonBytesFromSlice,
    StrictEntryPoint::CanonStringFromStr,
    StrictEntryPoint::CanonicalBytesFromSlice,
    StrictEntryPoint::StrictParseNoDuplicates,
];

struct NonExactNumberCase {
    name: &'static str,
    rejected_json: Vec<u8>,
    admitted_json: Vec<u8>,
}

fn assert_non_exact_number_is_rejected_by_strict_entrypoint(
    entrypoint: StrictEntryPoint,
    case: &NonExactNumberCase,
) {
    let entry_name = entrypoint.name();
    let case_name = case.name;

    assert!(
        !entrypoint.admits(&case.rejected_json),
        "[{entry_name}] {case_name}: non-exact / non-finite number must be REJECTED",
    );
    assert!(
        entrypoint.admits(&case.admitted_json),
        "[{entry_name}] {case_name}: positive control must be ADMITTED",
    );
}

fn run_case_against_all_strict_entry_points(case: &NonExactNumberCase) {
    for entrypoint in ALL_ENTRY_POINTS {
        assert_non_exact_number_is_rejected_by_strict_entrypoint(entrypoint, case);
    }
}

// ── Cases ─────────────────────────────────────────────────────────

fn positive_non_exact_integer_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "positive_non_exact_integer",
        // 2^53 + 1: not exactly representable as IEEE 754 binary64.
        rejected_json: b"{\"x\":9007199254740993}".to_vec(),
        // 2^53 - 1: I-JSON safe integer ceiling.
        admitted_json: b"{\"x\":9007199254740991}".to_vec(),
    }
}

fn negative_non_exact_integer_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "negative_non_exact_integer",
        rejected_json: b"{\"x\":-9007199254740993}".to_vec(),
        admitted_json: b"{\"x\":-9007199254740991}".to_vec(),
    }
}

fn positive_infinity_via_exponent_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "positive_infinity_via_exponent",
        // 1e500 overflows IEEE 754 binary64 to `+Infinity`.
        rejected_json: b"{\"x\":1e500}".to_vec(),
        admitted_json: b"{\"x\":1.5}".to_vec(),
    }
}

fn negative_infinity_via_exponent_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "negative_infinity_via_exponent",
        rejected_json: b"{\"x\":-1e500}".to_vec(),
        admitted_json: b"{\"x\":-1.5}".to_vec(),
    }
}

fn nested_non_exact_integer_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "nested_non_exact_integer",
        rejected_json: b"{\"a\":{\"b\":9007199254740993}}".to_vec(),
        admitted_json: b"{\"a\":{\"b\":9007199254740991}}".to_vec(),
    }
}

fn array_element_non_exact_integer_case() -> NonExactNumberCase {
    NonExactNumberCase {
        name: "array_element_non_exact_integer",
        rejected_json: b"[9007199254740993]".to_vec(),
        admitted_json: b"[9007199254740991]".to_vec(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn positive_non_exact_integer_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&positive_non_exact_integer_case());
}

#[test]
fn negative_non_exact_integer_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&negative_non_exact_integer_case());
}

#[test]
fn positive_infinity_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&positive_infinity_via_exponent_case());
}

#[test]
fn negative_infinity_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&negative_infinity_via_exponent_case());
}

#[test]
fn nested_non_exact_integer_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&nested_non_exact_integer_case());
}

#[test]
fn array_element_non_exact_integer_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&array_element_non_exact_integer_case());
}
