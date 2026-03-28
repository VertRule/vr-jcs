//! Differential tests: compare `vr_jcs` output against `serde_json` baseline.
//!
//! These tests verify that `vr_jcs` produces output that is:
//! 1. Valid JSON (`serde_json` can parse it back)
//! 2. Deterministic (same input always gives same output)
//! 3. Semantically equivalent to the input (round-trip preserves values)
//! 4. Compact (no whitespace outside strings)
//! 5. Key-sorted (objects sorted by UTF-16 code units)

use serde_json::{json, Value};

/// Parse the canonical output back and compare semantically.
fn round_trip(input: &Value) -> Result<Value, vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(input)?;
    serde_json::from_str(&canon).map_err(vr_jcs::JcsError::from)
}

/// Verify the canonical form is compact (no insignificant whitespace).
fn assert_compact(canon: &str) {
    let mut in_string = false;
    let mut escaped = false;
    for ch in canon.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            assert!(
                !ch.is_ascii_whitespace(),
                "found whitespace '{ch}' outside string in canonical output: {canon}"
            );
        }
    }
}

// ── Round-trip identity ────────────────────────────────────────────

#[test]
fn round_trip_flat_object() -> Result<(), vr_jcs::JcsError> {
    let input = json!({"b": 2, "a": 1});
    let output = round_trip(&input)?;
    assert_eq!(input, output);
    Ok(())
}

#[test]
fn round_trip_nested() -> Result<(), vr_jcs::JcsError> {
    let input = json!({"z": {"y": [1, 2, 3]}, "a": null});
    let output = round_trip(&input)?;
    assert_eq!(input, output);
    Ok(())
}

#[test]
fn round_trip_empty() -> Result<(), vr_jcs::JcsError> {
    for input in [json!({}), json!([]), json!(null), json!(true), json!(42)] {
        let output = round_trip(&input)?;
        assert_eq!(input, output);
    }
    Ok(())
}

// ── Compactness ────────────────────────────────────────────────────

#[test]
fn compact_object() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&json!({"a": 1, "b": 2}))?;
    assert_compact(&canon);
    Ok(())
}

#[test]
fn compact_array() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&json!([1, "hello", null, true]))?;
    assert_compact(&canon);
    Ok(())
}

#[test]
fn compact_nested() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&json!({"a": {"b": [1, {"c": 2}]}}))?;
    assert_compact(&canon);
    Ok(())
}

// ── Determinism ────────────────────────────────────────────────────

#[test]
fn deterministic_across_calls() -> Result<(), vr_jcs::JcsError> {
    let input = json!({"z": 1, "m": 2, "a": 3, "nested": {"z": 4, "a": 5}});
    let r1 = vr_jcs::to_canon_bytes(&input)?;
    let r2 = vr_jcs::to_canon_bytes(&input)?;
    assert_eq!(r1, r2);
    Ok(())
}

#[test]
fn deterministic_across_construction_order() -> Result<(), vr_jcs::JcsError> {
    let v1 = json!({"a": 1, "b": 2, "c": 3});
    let v2 = json!({"c": 3, "a": 1, "b": 2});
    assert_eq!(vr_jcs::to_canon_bytes(&v1)?, vr_jcs::to_canon_bytes(&v2)?);
    Ok(())
}

// ── Key ordering ───────────────────────────────────────────────────

#[test]
fn keys_sorted_ascii() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&json!({"z": 1, "a": 2, "m": 3}))?;
    assert_eq!(canon, r#"{"a":2,"m":3,"z":1}"#);
    Ok(())
}

#[test]
fn keys_sorted_utf16_not_utf8() -> Result<(), vr_jcs::JcsError> {
    // U+10000 (surrogate pair in UTF-16) sorts before U+E000 (single unit)
    let canon = vr_jcs::to_canon_string(&json!({
        "\u{E000}": "pua",
        "\u{10000}": "supp"
    }))?;
    assert!(
        canon.contains("supp") && canon.find("supp") < canon.find("pua"),
        "U+10000 should sort before U+E000 in UTF-16: {canon}"
    );
    Ok(())
}

// ── Cross-impl: vr_jcs vs serde_json ───────────────────────────────

#[test]
fn vr_jcs_output_is_valid_json() -> Result<(), vr_jcs::JcsError> {
    let inputs = [
        json!({"a": 1}),
        json!([1, 2, 3]),
        json!(null),
        json!(true),
        json!("hello"),
        json!(42),
        json!({"nested": {"deep": [1, {"k": "v"}]}}),
    ];
    for input in inputs {
        let canon = vr_jcs::to_canon_string(&input)?;
        let reparsed: Value = serde_json::from_str(&canon).map_err(vr_jcs::JcsError::from)?;
        assert_eq!(
            input, reparsed,
            "round-trip mismatch for {input}"
        );
    }
    Ok(())
}

/// Verify JCS sorts by UTF-16 code units, which differs from
/// lexicographic byte order for characters above the BMP.
#[test]
fn jcs_sorts_differently_from_byte_order_for_supplementary_chars() -> Result<(), vr_jcs::JcsError> {
    // U+10000 (Linear B Syllable B008 A) is D800 DC00 in UTF-16
    // U+E000 (Private Use Area) is E000 in UTF-16
    // UTF-16: D800 < E000, so U+10000 sorts first
    // UTF-8: F0 90 80 80 > EE 80 80, so U+E000 would sort first
    let mut map = serde_json::Map::new();
    map.insert("\u{E000}".to_string(), json!("pua"));
    map.insert("\u{10000}".to_string(), json!("supp"));
    let input = Value::Object(map);

    let canon = vr_jcs::to_canon_string(&input)?;

    // JCS (UTF-16 order): U+10000 before U+E000
    let supp_pos = canon.find("supp");
    let pua_pos = canon.find("pua");
    assert!(
        supp_pos < pua_pos,
        "U+10000 must sort before U+E000 in UTF-16 code-unit order: {canon}"
    );
    Ok(())
}

#[test]
fn blake3_digest_matches_across_construction_orders() -> Result<(), vr_jcs::JcsError> {
    let v1 = json!({"receipt_type": "governance", "payload": {"action": "test"}, "version": 2});
    let v2 = json!({"version": 2, "receipt_type": "governance", "payload": {"action": "test"}});

    let d1 = blake3::hash(&vr_jcs::to_canon_bytes(&v1)?);
    let d2 = blake3::hash(&vr_jcs::to_canon_bytes(&v2)?);
    assert_eq!(d1, d2, "same logical JSON must produce same BLAKE3 digest regardless of field order");
    Ok(())
}

// ── No private serde_json internals ────────────────────────────────

#[test]
fn no_private_sentinel_in_output() -> Result<(), vr_jcs::JcsError> {
    // Ensure canonical output never contains serde_json's internal sentinel
    let inputs = [
        json!(42),
        json!(1.5),
        json!({"a": 1.5, "b": 42}),
        json!([1, 2.5, 3]),
    ];
    for input in inputs {
        let canon = vr_jcs::to_canon_string(&input)?;
        assert!(
            !canon.contains("serde_json"),
            "canonical output must not contain serde_json internals: {canon}"
        );
        assert!(
            !canon.contains("private"),
            "canonical output must not contain 'private': {canon}"
        );
    }
    Ok(())
}
