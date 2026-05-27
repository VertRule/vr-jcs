//! ADR-001 Ratification Criterion #4 — strict path admits up to and
//! rejects beyond `MAX_NESTING_DEPTH = 128`.
//!
//! Pins **both sides** of the depth boundary (the file is named
//! `strict_rejects_depth_boundary.rs`, not `..._depth_overflow.rs`,
//! because the admit edge is the load-bearing invariant, not just the
//! reject edge). The strict path's depth check is `depth > MAX_NESTING_DEPTH`
//! so a scalar reached at recursion depth 128 admits and depth 129 rejects.
//!
//! Coverage is structural:
//!
//! - object-only nesting at the boundary (`{"x":...{"x":1}...}` with N wraps),
//! - array-only nesting at the boundary (`[[...[1]...]]` with N elements),
//! - mixed object/array nesting at the boundary (alternates per level).
//!
//! Each case is a paired fixture: `rejected_json` is depth 129,
//! `admitted_json` is depth 128. Both depths use the same shape so
//! the rejection is uniquely attributable to one extra level of nesting.
//!
//! Fixtures are generated programmatically rather than hand-written.
//!
//! ADR-001 binds the admission *predicate*, not the error taxonomy; the
//! helper inspects only `is_err()` / `is_ok()`. Stable machine-readable
//! error projection is the obligation of ADR-003.

use vr_jcs::{
    canonical_bytes_from_slice, strict_parse, to_canon_bytes_from_slice, to_canon_string_from_str,
};

const MAX_DEPTH: usize = 128;
const ONE_PAST_MAX: usize = 129;

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

struct DepthBoundaryCase {
    name: &'static str,
    rejected_json: Vec<u8>,
    admitted_json: Vec<u8>,
}

fn assert_depth_boundary_is_enforced_by_strict_entrypoint(
    entrypoint: StrictEntryPoint,
    case: &DepthBoundaryCase,
) {
    let entry_name = entrypoint.name();
    let case_name = case.name;

    assert!(
        !entrypoint.admits(&case.rejected_json),
        "[{entry_name}] {case_name}: depth {ONE_PAST_MAX} must be REJECTED",
    );
    assert!(
        entrypoint.admits(&case.admitted_json),
        "[{entry_name}] {case_name}: depth {MAX_DEPTH} must be ADMITTED",
    );
}

fn run_case_against_all_strict_entry_points(case: &DepthBoundaryCase) {
    for entrypoint in ALL_ENTRY_POINTS {
        assert_depth_boundary_is_enforced_by_strict_entrypoint(entrypoint, case);
    }
}

// ── Generators ────────────────────────────────────────────────────

fn nested_object_with_scalar_at_depth(depth: usize) -> String {
    let mut json = String::with_capacity(depth * 6 + 1);
    for _ in 0..depth {
        json.push_str(r#"{"x":"#);
    }
    json.push('1');
    for _ in 0..depth {
        json.push('}');
    }
    json
}

fn nested_array_with_scalar_at_depth(depth: usize) -> String {
    let mut json = String::with_capacity(depth * 2 + 1);
    for _ in 0..depth {
        json.push('[');
    }
    json.push('1');
    for _ in 0..depth {
        json.push(']');
    }
    json
}

fn nested_mixed_with_scalar_at_depth(depth: usize) -> String {
    let mut json = String::with_capacity(depth * 6 + 1);
    let mut closers: Vec<char> = Vec::with_capacity(depth);
    for level in 0..depth {
        if level % 2 == 0 {
            json.push_str(r#"{"x":"#);
            closers.push('}');
        } else {
            json.push('[');
            closers.push(']');
        }
    }
    json.push('1');
    for closer in closers.into_iter().rev() {
        json.push(closer);
    }
    json
}

// ── Cases ─────────────────────────────────────────────────────────

fn object_only_depth_boundary_case() -> DepthBoundaryCase {
    DepthBoundaryCase {
        name: "object_only_depth_boundary",
        rejected_json: nested_object_with_scalar_at_depth(ONE_PAST_MAX).into_bytes(),
        admitted_json: nested_object_with_scalar_at_depth(MAX_DEPTH).into_bytes(),
    }
}

fn array_only_depth_boundary_case() -> DepthBoundaryCase {
    DepthBoundaryCase {
        name: "array_only_depth_boundary",
        rejected_json: nested_array_with_scalar_at_depth(ONE_PAST_MAX).into_bytes(),
        admitted_json: nested_array_with_scalar_at_depth(MAX_DEPTH).into_bytes(),
    }
}

fn mixed_depth_boundary_case() -> DepthBoundaryCase {
    DepthBoundaryCase {
        name: "mixed_depth_boundary",
        rejected_json: nested_mixed_with_scalar_at_depth(ONE_PAST_MAX).into_bytes(),
        admitted_json: nested_mixed_with_scalar_at_depth(MAX_DEPTH).into_bytes(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn object_only_depth_boundary_enforced_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&object_only_depth_boundary_case());
}

#[test]
fn array_only_depth_boundary_enforced_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&array_only_depth_boundary_case());
}

#[test]
fn mixed_depth_boundary_enforced_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&mixed_depth_boundary_case());
}
