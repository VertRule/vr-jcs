//! ADR-001 Ratification Criterion #1 — strict path rejects ambiguous
//! untrusted JSON (duplicate-key ambiguity).
//!
//! Proves differential admission across every strict-path entry point:
//!
//! - rejects a syntactically valid object whose member names are duplicated,
//! - admits the corresponding positive control with the duplicate removed.
//!
//! Coverage is structural: top-level, nested object, array element,
//! same-value repetition, post-decoded-Unicode member names, and traversal
//! at admitted depth below `MAX_NESTING_DEPTH`. Depth-overflow rejection
//! belongs to a separate resource-bound admission test
//! (`strict_rejects_depth_boundary.rs`).
//!
//! ADR-001 binds the admission *predicate*, not the error taxonomy; the
//! helper intentionally inspects only `is_err()` / `is_ok()`. Stable
//! machine-readable error projection is the obligation of ADR-003.

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

struct DuplicateKeyCase {
    name: &'static str,
    duplicate_json: Vec<u8>,
    control_json: Vec<u8>,
}

fn assert_duplicate_key_is_rejected_by_strict_entrypoint(
    entrypoint: StrictEntryPoint,
    case: &DuplicateKeyCase,
) {
    let entry_name = entrypoint.name();
    let case_name = case.name;

    assert!(
        !entrypoint.admits(&case.duplicate_json),
        "[{entry_name}] {case_name}: duplicate-key input must be REJECTED",
    );
    assert!(
        entrypoint.admits(&case.control_json),
        "[{entry_name}] {case_name}: positive control must be ADMITTED",
    );
}

fn run_case_against_all_strict_entry_points(case: &DuplicateKeyCase) {
    for entrypoint in ALL_ENTRY_POINTS {
        assert_duplicate_key_is_rejected_by_strict_entrypoint(entrypoint, case);
    }
}

// ── Cases ─────────────────────────────────────────────────────────

fn top_level_duplicate_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "top_level_duplicate",
        duplicate_json: br#"{"a":1,"a":2}"#.to_vec(),
        control_json: br#"{"a":1}"#.to_vec(),
    }
}

fn nested_object_duplicate_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "nested_object_duplicate",
        duplicate_json: br#"{"x":{"a":1,"a":2}}"#.to_vec(),
        control_json: br#"{"x":{"a":1}}"#.to_vec(),
    }
}

fn array_element_duplicate_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "array_element_duplicate",
        duplicate_json: br#"[{"a":1,"a":2}]"#.to_vec(),
        control_json: br#"[{"a":1}]"#.to_vec(),
    }
}

fn same_value_duplicate_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "same_value_duplicate",
        duplicate_json: br#"{"a":1,"a":1}"#.to_vec(),
        control_json: br#"{"a":1}"#.to_vec(),
    }
}

fn unicode_member_name_duplicate_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "unicode_member_name_duplicate",
        duplicate_json: r#"{"é":1,"é":2}"#.as_bytes().to_vec(),
        control_json: r#"{"é":1}"#.as_bytes().to_vec(),
    }
}

fn depth_64_duplicate_key_case() -> DuplicateKeyCase {
    DuplicateKeyCase {
        name: "depth_64_duplicate_key",
        duplicate_json: nested_object_with_duplicate_at_depth(64).into_bytes(),
        control_json: nested_object_control_at_depth(64).into_bytes(),
    }
}

fn nested_object_with_duplicate_at_depth(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"x":"#);
    }
    json.push_str(r#"{"a":1,"a":2}"#);
    for _ in 0..depth {
        json.push('}');
    }
    json
}

fn nested_object_control_at_depth(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"x":"#);
    }
    json.push_str(r#"{"a":1}"#);
    for _ in 0..depth {
        json.push('}');
    }
    json
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn top_level_duplicate_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&top_level_duplicate_case());
}

#[test]
fn nested_object_duplicate_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&nested_object_duplicate_case());
}

#[test]
fn array_element_duplicate_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&array_element_duplicate_case());
}

#[test]
fn same_value_duplicate_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&same_value_duplicate_case());
}

#[test]
fn unicode_member_name_duplicate_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&unicode_member_name_duplicate_case());
}

#[test]
fn duplicate_key_at_depth_64_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&depth_64_duplicate_key_case());
}
