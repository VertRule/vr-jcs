//! ADR-001 Ratification Criterion #2 — strict path rejects I-JSON
//! string and member-name invalidity.
//!
//! Proves differential admission across every strict-path entry point:
//!
//! - rejects JSON whose string values or object property names contain
//!   I-JSON-forbidden Unicode noncharacters
//!   (`U+FDD0..=U+FDEF`, and any code point with `code & 0xFFFE == 0xFFFE`,
//!   covering U+xFFFE / U+xFFFF in every plane),
//! - admits the corresponding positive control with the noncharacter
//!   replaced by a benign code point.
//!
//! Coverage is structural: lower edge of the contiguous `FDD0..FDEF`
//! range, upper edge of the contiguous range, BMP `xFFFE`, BMP `xFFFF`,
//! a supplementary-plane `xFFFE` (proving the rule extends past the BMP
//! via JSON surrogate-pair escape), and one property-name case (proving
//! member-name validation, not only string-value validation).
//!
//! Property-name cases deliberately avoid the documented `'$'`-prefix
//! bypass for `serde_json` `arbitrary_precision` sentinels.
//!
//! Noncharacters are inserted via JSON Unicode escapes so the source
//! bytes remain ASCII. The two bytes for the JSON escape introducer are
//! written as `\x5C\x75` (i.e. `\` then `u`) in Rust byte-string literals
//! because the literal text `\u` triggers Rust's own Unicode-escape
//! parser. The strict parser decodes the JSON escape and runs
//! `validate_string_contents` on the resulting `String`.
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

struct InvalidStringCase {
    name: &'static str,
    rejected_json: Vec<u8>,
    admitted_json: Vec<u8>,
}

fn assert_invalid_string_is_rejected_by_strict_entrypoint(
    entrypoint: StrictEntryPoint,
    case: &InvalidStringCase,
) {
    let entry_name = entrypoint.name();
    let case_name = case.name;

    assert!(
        !entrypoint.admits(&case.rejected_json),
        "[{entry_name}] {case_name}: I-JSON-invalid input must be REJECTED",
    );
    assert!(
        entrypoint.admits(&case.admitted_json),
        "[{entry_name}] {case_name}: positive control must be ADMITTED",
    );
}

fn run_case_against_all_strict_entry_points(case: &InvalidStringCase) {
    for entrypoint in ALL_ENTRY_POINTS {
        assert_invalid_string_is_rejected_by_strict_entrypoint(entrypoint, case);
    }
}

// ── Helpers ───────────────────────────────────────────────────────
//
// `\x5C\x75` is the two-byte sequence for JSON's `\u` escape introducer
// (ASCII backslash + ASCII `u`). Written this way the byte-string literal
// stays ASCII *and* avoids tripping Rust's own `\u{...}` parser.

fn json_object_with_bmp_escape_in_value(hex4: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"{\"x\":\"\x5C\x75");
    bytes.extend_from_slice(hex4.as_bytes());
    bytes.extend_from_slice(b"\"}");
    bytes
}

fn json_object_with_surrogate_pair_in_value(hi4: &str, lo4: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"{\"x\":\"\x5C\x75");
    bytes.extend_from_slice(hi4.as_bytes());
    bytes.extend_from_slice(b"\x5C\x75");
    bytes.extend_from_slice(lo4.as_bytes());
    bytes.extend_from_slice(b"\"}");
    bytes
}

fn json_object_with_bmp_escape_as_key(hex4: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"{\"\x5C\x75");
    bytes.extend_from_slice(hex4.as_bytes());
    bytes.extend_from_slice(b"\":1}");
    bytes
}

fn admitted_value_control() -> Vec<u8> {
    b"{\"x\":\"a\"}".to_vec()
}

fn admitted_key_control() -> Vec<u8> {
    b"{\"a\":1}".to_vec()
}

// ── Cases ─────────────────────────────────────────────────────────

fn value_contains_fdd0_case() -> InvalidStringCase {
    InvalidStringCase {
        name: "value_contains_fdd0",
        rejected_json: json_object_with_bmp_escape_in_value("FDD0"),
        admitted_json: admitted_value_control(),
    }
}

fn value_contains_fdef_case() -> InvalidStringCase {
    InvalidStringCase {
        name: "value_contains_fdef",
        rejected_json: json_object_with_bmp_escape_in_value("FDEF"),
        admitted_json: admitted_value_control(),
    }
}

fn value_contains_bmp_xfffe_case() -> InvalidStringCase {
    InvalidStringCase {
        name: "value_contains_bmp_xfffe",
        rejected_json: json_object_with_bmp_escape_in_value("FFFE"),
        admitted_json: admitted_value_control(),
    }
}

fn value_contains_bmp_xffff_case() -> InvalidStringCase {
    InvalidStringCase {
        name: "value_contains_bmp_xffff",
        rejected_json: json_object_with_bmp_escape_in_value("FFFF"),
        admitted_json: admitted_value_control(),
    }
}

fn value_contains_supplementary_xfffe_case() -> InvalidStringCase {
    // U+1FFFE encoded as a JSON surrogate pair: high = U+D83F, low = U+DFFE.
    // Bottom 16 bits of U+1FFFE are 0xFFFE, so it matches `is_noncharacter`
    // outside the Basic Multilingual Plane.
    InvalidStringCase {
        name: "value_contains_supplementary_xfffe",
        rejected_json: json_object_with_surrogate_pair_in_value("D83F", "DFFE"),
        admitted_json: admitted_value_control(),
    }
}

fn object_property_name_contains_noncharacter_case() -> InvalidStringCase {
    // Decoded key is U+FDD0 (not `'$'`), so the documented serde_json-
    // sentinel bypass in `strict_parse` does not apply.
    InvalidStringCase {
        name: "object_property_name_contains_noncharacter",
        rejected_json: json_object_with_bmp_escape_as_key("FDD0"),
        admitted_json: admitted_key_control(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[test]
fn value_with_fdd0_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&value_contains_fdd0_case());
}

#[test]
fn value_with_fdef_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&value_contains_fdef_case());
}

#[test]
fn value_with_bmp_xfffe_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&value_contains_bmp_xfffe_case());
}

#[test]
fn value_with_bmp_xffff_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&value_contains_bmp_xffff_case());
}

#[test]
fn value_with_supplementary_xfffe_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&value_contains_supplementary_xfffe_case());
}

#[test]
fn property_name_with_noncharacter_rejected_by_every_strict_entry_point() {
    run_case_against_all_strict_entry_points(&object_property_name_contains_noncharacter_case());
}
