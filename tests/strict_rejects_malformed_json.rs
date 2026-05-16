//! ADR-001 Ratification Criterion #5 — strict path rejects syntactically
//! invalid JSON before any canonical-emit work.
//!
//! Proves differential admission across every strict-path entry point:
//!
//! - rejects input that is not well-formed JSON per RFC 8259,
//! - admits the corresponding positive control with the syntax defect
//!   repaired.
//!
//! Coverage is structural — each case isolates one distinct class of
//! malformedness:
//!
//! - unclosed object (truncation),
//! - unclosed array (truncation, different structure),
//! - trailing comma inside an object (separator misuse),
//! - trailing garbage after a valid value (exercises the
//!   `serde_json::Deserializer::end` check in the strict path),
//! - unquoted property name (RFC 8259 requires JSON strings as keys).
//!
//! This file does not cover duplicate keys, I-JSON string invalidity,
//! number admission, or depth — those are Ratification Criteria #1, #2,
//! #3, and #4 respectively.
//!
//! ADR-001 binds the admission *predicate*, not the error taxonomy; the
//! helper inspects only `is_err()` / `is_ok()`. Stable machine-readable
//! error projection is the obligation of ADR-003.

use vr_jcs::{
    canonical_bytes_from_slice, strict_parse, to_canon_bytes_from_slice,
    to_canon_string_from_str,
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
            Self::StrictParseNoDuplicates => {
                "strict_parse::parse_json_value_no_duplicates"
            }
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

struct MalformedJsonCase {
    name: &'static str,
    rejected_json: Vec<u8>,
    admitted_json: Vec<u8>,
}

fn assert_malformed_json_is_rejected_by_strict_entrypoint(
    entrypoint: StrictEntryPoint,
    case: &MalformedJsonCase,
) {
    let entry_name = entrypoint.name();
    let case_name = case.name;

    assert!(
        !entrypoint.admits(&case.rejected_json),
        "[{entry_name}] {case_name}: malformed JSON must be REJECTED",
    );
    assert!(
        entrypoint.admits(&case.admitted_json),
        "[{entry_name}] {case_name}: repaired positive control must be ADMITTED",
    );
}

fn run_case_against_all_strict_entry_points(case: &MalformedJsonCase) {
    for entrypoint in ALL_ENTRY_POINTS {
        assert_malformed_json_is_rejected_by_strict_entrypoint(entrypoint, case);
    }
}

// ── Cases ─────────────────────────────────────────────────────────

fn unclosed_object_case() -> MalformedJsonCase {
    MalformedJsonCase {
        name: "unclosed_object",
        rejected_json: br#"{"x":1"#.to_vec(),
        admitted_json: br#"{"x":1}"#.to_vec(),
    }
}

fn unclosed_array_case() -> MalformedJsonCase {
    MalformedJsonCase {
        name: "unclosed_array",
        rejected_json: b"[1,2".to_vec(),
        admitted_json: b"[1,2]".to_vec(),
    }
}

fn trailing_comma_in_object_case() -> MalformedJsonCase {
    MalformedJsonCase {
        name: "trailing_comma_in_object",
        rejected_json: br#"{"x":1,}"#.to_vec(),
        admitted_json: br#"{"x":1}"#.to_vec(),
    }
}

fn trailing_garbage_after_value_case() -> MalformedJsonCase {
    // Exercises the `deserializer.end()` check after a valid value:
    // `1` parses as a complete JSON number, then `xyz` is rejected as
    // extra input.
    MalformedJsonCase {
        name: "trailing_garbage_after_value",
        rejected_json: b"1xyz".to_vec(),
        admitted_json: b"1".to_vec(),
    }
}

fn unquoted_property_name_case() -> MalformedJsonCase {
    MalformedJsonCase {
        name: "unquoted_property_name",
        rejected_json: b"{x:1}".to_vec(),
        admitted_json: br#"{"x":1}"#.to_vec(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn unclosed_object_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&unclosed_object_case());
}

#[test]
fn unclosed_array_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&unclosed_array_case());
}

#[test]
fn trailing_comma_in_object_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&trailing_comma_in_object_case());
}

#[test]
fn trailing_garbage_after_value_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&trailing_garbage_after_value_case());
}

#[test]
fn unquoted_property_name_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&unquoted_property_name_case());
}
