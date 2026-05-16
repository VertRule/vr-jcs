//! ADR-003 Ratification Criterion C2 — strict-path duplicate-key
//! detection routes to `JcsError::DuplicateKey`, not the generic
//! `JcsError::Json`.
//!
//! Three tests pin the routing:
//!
//! 1. `parse_json_value_no_duplicates` directly returns `DuplicateKey`
//!    with code `"duplicate-key"` for duplicate-key input.
//! 2. The byte-emitting strict entry points (`to_canon_bytes_from_slice`)
//!    also surface `DuplicateKey` (they delegate to the same parser).
//! 3. **Control case:** a non-duplicate-key serde parse failure
//!    (`b"not json"`) still produces `JcsError::Json` with code
//!    `"json-parse"` — the sentinel detection does not over-classify.

use vr_jcs::JcsError;

#[test]
fn duplicate_key_routes_via_parse_json_value_no_duplicates() {
    let result =
        vr_jcs::strict_parse::parse_json_value_no_duplicates(br#"{"a":1,"a":2}"#);
    assert!(result.is_err(), "duplicate-key input must be rejected");
    if let Err(err) = result {
        assert!(
            matches!(&err, JcsError::DuplicateKey(_)),
            "expected JcsError::DuplicateKey, got {err:?}",
        );
        assert_eq!(err.code(), "duplicate-key");
    }
}

#[test]
fn duplicate_key_routes_via_byte_emit_path() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"a":1,"a":2}"#);
    assert!(result.is_err(), "duplicate-key input must be rejected");
    if let Err(err) = result {
        assert!(
            matches!(&err, JcsError::DuplicateKey(_)),
            "expected JcsError::DuplicateKey, got {err:?}",
        );
        assert_eq!(err.code(), "duplicate-key");
    }
}

#[test]
fn non_duplicate_parse_error_stays_in_json_variant() {
    // Control case: malformed input that is NOT a duplicate-key case.
    // The sentinel substring `"duplicate property name \`"` MUST NOT
    // be over-classified — generic syntax errors stay in `JcsError::Json`
    // with code `"json-parse"`.
    let result = vr_jcs::strict_parse::parse_json_value_no_duplicates(b"not json");
    assert!(result.is_err(), "malformed JSON must be rejected");
    if let Err(err) = result {
        assert!(
            matches!(&err, JcsError::Json(_)),
            "non-duplicate parse error must stay in JcsError::Json, got {err:?}",
        );
        assert_eq!(err.code(), "json-parse");
    }
}
