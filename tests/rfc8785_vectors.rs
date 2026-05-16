//! ADR-001 Ratification Criterion #7 — RFC 8785 canonical-emit conformance.
//!
//! Loads the committed vector set from `test-vectors/rfc8785.json` and
//! pins each `input → expected` pair against the **three byte-emitting**
//! strict entry points:
//!
//! - `to_canon_bytes_from_slice`
//! - `to_canon_string_from_str`
//! - `canonical_bytes_from_slice`
//!
//! `strict_parse::parse_json_value_no_duplicates` is **excluded** because
//! it is parse-only and does not emit canonical bytes. This file ratifies
//! the canonical-*emit* contract; admission rejection is Ratification
//! Criteria #1–#5.
//!
//! Two additional inline cases pin ADR-bound claims that are not covered
//! by an explicit vector in `rfc8785.json`:
//!
//! - **`whitespace_removed`** — insignificant whitespace in source bytes
//!   is stripped on canonical emit (RFC 8785 §3.2.7 "no insignificant
//!   whitespace" applied to source-byte input rather than parsed-value
//!   input),
//! - **`array_order_preserved`** — array element order is retained verbatim
//!   (canonicalization sorts object keys, not array elements).

use vr_jcs::{
    canonical_bytes_from_slice, to_canon_bytes_from_slice, to_canon_string_from_str,
    JcsError,
};

const VECTORS_JSON: &str = include_str!("../test-vectors/rfc8785.json");

#[derive(serde::Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    id: String,
    input: serde_json::Value,
    expected: String,
}

fn run_emit_vector_through_byte_emitting_entry_points(
    id: &str,
    input_str: &str,
    expected: &[u8],
) -> Result<(), JcsError> {
    let input_bytes = input_str.as_bytes();

    let bytes_out = to_canon_bytes_from_slice(input_bytes)?;
    assert_eq!(
        bytes_out.as_slice(),
        expected,
        "[{id}] to_canon_bytes_from_slice: bytes mismatch",
    );

    let canon = canonical_bytes_from_slice(input_bytes)?;
    assert_eq!(
        canon.as_slice(),
        expected,
        "[{id}] canonical_bytes_from_slice: bytes mismatch",
    );

    let string_out = to_canon_string_from_str(input_str)?;
    assert_eq!(
        string_out.as_bytes(),
        expected,
        "[{id}] to_canon_string_from_str: bytes mismatch",
    );

    Ok(())
}

#[test]
fn rfc8785_vector_set_emits_canonical_bytes() -> Result<(), JcsError> {
    let vector_file: VectorFile =
        serde_json::from_str(VECTORS_JSON).map_err(JcsError::from)?;

    assert!(
        !vector_file.vectors.is_empty(),
        "rfc8785.json declared an empty vector set",
    );

    for vector in &vector_file.vectors {
        // Re-serialize the parsed input as JSON bytes. `serde_json` is
        // configured with `preserve_order`, so insertion order survives
        // the round trip and the strict parser actually has to sort keys
        // on emit (rather than seeing them already canonically ordered).
        let input_str = serde_json::to_string(&vector.input).map_err(JcsError::from)?;
        run_emit_vector_through_byte_emitting_entry_points(
            &vector.id,
            &input_str,
            vector.expected.as_bytes(),
        )?;
    }
    Ok(())
}

#[test]
fn insignificant_whitespace_in_source_bytes_is_stripped() -> Result<(), JcsError> {
    let input_str = r#"  {  "x"  :  1  ,  "y"  :  2  }  "#;
    let expected = br#"{"x":1,"y":2}"#;

    run_emit_vector_through_byte_emitting_entry_points(
        "whitespace_removed",
        input_str,
        expected,
    )
}

#[test]
fn array_element_order_is_preserved_verbatim() -> Result<(), JcsError> {
    let input_str = r#"["beta","alpha","gamma","aleph"]"#;
    let expected = br#"["beta","alpha","gamma","aleph"]"#;

    run_emit_vector_through_byte_emitting_entry_points(
        "array_order_preserved",
        input_str,
        expected,
    )
}
