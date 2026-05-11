use super::*;
use serde_json::{json, Value};

/// Non-deprecated helper: Value → canonical string via internal path.
fn canon_str(value: &serde_json::Value) -> Result<String, JcsError> {
    let bytes = to_canon_bytes_value(value)?;
    String::from_utf8(bytes)
        .map_err(|e| JcsError::InvalidString(format!("output was not UTF-8: {e}")))
}

// ── Key sorting (UTF-16 code units, RFC 8785 §3.2.3) ──────────────

#[test]
fn sorts_ascii_keys() -> Result<(), JcsError> {
    let value = json!({"z": 1, "a": 2, "m": 3});
    assert_eq!(canon_str(&value)?, r#"{"a":2,"m":3,"z":1}"#);
    Ok(())
}

#[test]
fn sorts_keys_by_utf16_code_units() -> Result<(), JcsError> {
    let value = json!({
        "\u{E000}": 2,
        "\u{10000}": 1
    });
    let expected = format!(r#"{{"{}":1,"{}":2}}"#, '\u{10000}', '\u{E000}');
    assert_eq!(canon_str(&value)?, expected);
    Ok(())
}

#[test]
fn rfc_8785_property_sorting_example() -> Result<(), JcsError> {
    let input = r#"{
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\ud83d\ude00": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis"
    }"#;
    let string = to_canon_string_from_str(input)?;
    let expected = concat!(
        "{\"\\r\":\"Carriage Return\",",
        "\"1\":\"One\",",
        "\"\u{0080}\":\"Control\",",
        "\"\u{00F6}\":\"Latin Small Letter O With Diaeresis\",",
        "\"\u{20AC}\":\"Euro Sign\",",
        "\"\u{1F600}\":\"Emoji: Grinning Face\",",
        "\"\u{FB33}\":\"Hebrew Letter Dalet With Dagesh\"}"
    );
    assert_eq!(string, expected);
    Ok(())
}

// ── Number rendering (ECMAScript, RFC 8785 §3.2.2.3) ──────────────

#[test]
fn rfc_8785_primitive_example() -> Result<(), JcsError> {
    let input = r#"{
        "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
        "literals": [null, true, false]
    }"#;
    let string = to_canon_string_from_str(input)?;
    let expected = concat!(
        "{\"literals\":[null,true,false],",
        "\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],",
        "\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
    assert_eq!(string, expected);
    Ok(())
}

#[test]
fn ecmascript_number_rendering() -> Result<(), JcsError> {
    let value = json!([
        1e-6,
        0.000_001_2,
        1e-7,
        1e20,
        1e21,
        1_000_000.0,
        -0.0,
        0.0,
        1.0
    ]);
    assert_eq!(
        canon_str(&value)?,
        "[0.000001,0.0000012,1e-7,100000000000000000000,1e+21,1000000,0,0,1]"
    );
    Ok(())
}

#[test]
fn rejects_non_exact_large_integer() {
    let value = json!(9_007_199_254_740_993u64);
    let result = to_canon_bytes_value(&value);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(err.to_string().contains("not exactly representable"));
    }
}

#[test]
fn accepts_exact_large_integer() -> Result<(), JcsError> {
    let value = json!(9_007_199_254_740_992u64);
    assert_eq!(canon_str(&value)?, "9007199254740992");
    Ok(())
}

// ── Structure handling ─────────────────────────────────────────────

#[test]
fn preserves_array_order_and_recurses_objects() -> Result<(), JcsError> {
    let value = json!({
        "z": [{"b": 2, "a": 1}],
        "a": [{"b": 4, "a": 3}]
    });
    assert_eq!(
        canon_str(&value)?,
        r#"{"a":[{"a":3,"b":4}],"z":[{"a":1,"b":2}]}"#
    );
    Ok(())
}

#[test]
fn deeply_nested_canonicalization() -> Result<(), JcsError> {
    let mut v = json!({
        "z": { "z": { "z": 1, "a": 2 }, "a": 3 },
        "a": 4
    });
    canonicalize(&mut v)?;
    assert_eq!(canon_str(&v)?, r#"{"a":4,"z":{"a":3,"z":{"a":2,"z":1}}}"#);
    Ok(())
}

#[test]
fn mixed_types_in_object() -> Result<(), JcsError> {
    let value = json!({
        "z_bool": true,
        "a_null": null,
        "m_num": 42,
        "b_str": "hello",
        "c_arr": [1, 2, 3]
    });
    assert_eq!(
        canon_str(&value)?,
        r#"{"a_null":null,"b_str":"hello","c_arr":[1,2,3],"m_num":42,"z_bool":true}"#
    );
    Ok(())
}

#[test]
fn empty_object() -> Result<(), JcsError> {
    let mut v = json!({});
    canonicalize(&mut v)?;
    assert_eq!(canon_str(&v)?, "{}");
    Ok(())
}

#[test]
fn scalar_is_noop() -> Result<(), JcsError> {
    let mut v = json!(42);
    canonicalize(&mut v)?;
    assert_eq!(v, json!(42));
    Ok(())
}

// ── Determinism ────────────────────────────────────────────────────

#[test]
fn shuffle_invariant() -> Result<(), JcsError> {
    let v1 = json!({"id": 123, "timestamp": 456_789, "data": {"x": 1, "y": 2, "z": 3}});
    let v2 = json!({"data": {"z": 3, "x": 1, "y": 2}, "timestamp": 456_789, "id": 123});
    assert_eq!(to_canon_bytes_value(&v1)?, to_canon_bytes_value(&v2)?);
    Ok(())
}

#[test]
fn shuffle_invariant_hashing() -> Result<(), JcsError> {
    let v1 = json!({"z": 1, "a": 2});
    let v2 = json!({"a": 2, "z": 1});
    let hash1 = blake3::hash(&to_canon_bytes_value(&v1)?);
    let hash2 = blake3::hash(&to_canon_bytes_value(&v2)?);
    assert_eq!(hash1, hash2);
    Ok(())
}

// ── Validation (I-JSON, duplicate rejection) ───────────────────────

#[test]
fn rejects_duplicate_property_names() {
    let result = to_canon_bytes_from_slice(br#"{"a": 1, "a": 2}"#);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(err.to_string().contains("duplicate property name"));
    }
}

#[test]
fn rejects_nested_duplicate_property_names() {
    let result = to_canon_bytes_from_slice(br#"{"outer": {"a": 1, "a": 2}}"#);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(err.to_string().contains("duplicate property name"));
    }
}

#[test]
fn rejects_noncharacters() {
    let result = to_canon_string_from_str(r#"{"bad":"\uFDD0"}"#);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(err.to_string().contains("forbidden noncharacter"));
    }
}

// ── Nesting depth limit ───────────────────────────────────────────

fn build_nested_json(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"a":"#);
    }
    json.push('1');
    for _ in 0..depth {
        json.push('}');
    }
    json
}

fn build_nested_value(depth: usize) -> Value {
    let mut v = json!(1);
    for _ in 0..depth {
        v = json!({"a": v});
    }
    v
}

#[test]
fn depth_at_limit_accepted_emit() -> Result<(), JcsError> {
    let json = build_nested_json(MAX_NESTING_DEPTH);
    let result = to_canon_string_from_str(&json)?;
    assert!(!result.is_empty());
    Ok(())
}

#[test]
fn depth_beyond_limit_rejected_emit() {
    let json = build_nested_json(MAX_NESTING_DEPTH + 1);
    let result = to_canon_string_from_str(&json);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(
            err.to_string().contains("nesting depth exceeded"),
            "expected depth error, got: {err}"
        );
    }
}

#[test]
fn depth_at_limit_accepted_canonicalize() -> Result<(), JcsError> {
    let mut v = build_nested_value(MAX_NESTING_DEPTH);
    canonicalize(&mut v)?;
    Ok(())
}

#[test]
fn depth_beyond_limit_rejected_canonicalize() {
    let mut v = build_nested_value(MAX_NESTING_DEPTH + 1);
    let result = canonicalize(&mut v);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(
            err.to_string().contains("nesting depth exceeded"),
            "expected depth error, got: {err}"
        );
    }
}

#[test]
fn extreme_depth_does_not_stack_overflow() {
    let json = build_nested_json(10_000);
    let result = to_canon_string_from_str(&json);
    assert!(result.is_err());
}

// ── Error display ──────────────────────────────────────────────────

#[test]
fn error_display_json() {
    let err = JcsError::Json(serde_json::Error::io(std::io::Error::other("test")));
    assert!(err.to_string().contains("JCS JSON processing failed"));
}

#[test]
fn error_display_number() {
    let err = JcsError::InvalidNumber("bad".to_string());
    assert!(err.to_string().contains("number validation failed"));
}

#[test]
fn error_display_string() {
    let err = JcsError::InvalidString("bad".to_string());
    assert!(err.to_string().contains("string validation failed"));
}

#[test]
fn error_display_nesting_depth() {
    let err = JcsError::NestingDepthExceeded;
    assert!(err.to_string().contains("nesting depth exceeded"));
}

// ── Deprecated typed path: depth parity only ──────────────────────
//
// Struct serialization and cross-path comparison tests live in
// tests/deprecated_typed_api.rs. These depth tests remain here
// because they share the internal build_nested_value helper.

mod deprecated_typed_path_depth {
    #![allow(deprecated)]

    use super::*;

    #[test]
    fn at_limit_accepted() -> Result<(), JcsError> {
        let v = build_nested_value(MAX_NESTING_DEPTH);
        let result = to_canon_bytes(&v)?;
        assert!(!result.is_empty());
        Ok(())
    }

    #[test]
    fn beyond_limit_rejected() {
        let v = build_nested_value(MAX_NESTING_DEPTH + 1);
        let result = to_canon_bytes(&v);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string().contains("nesting depth exceeded"),
                "expected depth error, got: {err}"
            );
        }
    }
}

// ── BLAKE3 convenience (to_canon_blake3_digest*) ──

#[test]
fn to_canon_blake3_digest_matches_manual_pairing() -> Result<(), JcsError> {
    let value = json!({"z_field": 1, "a_field": 2});
    let manual = {
        let bytes = to_canon_bytes_value(&value)?;
        *blake3::hash(&bytes).as_bytes()
    };
    let combined = to_canon_blake3_digest(&value)?;
    assert_eq!(manual, combined, "wrapper must match manual pairing");
    Ok(())
}

#[test]
fn to_canon_blake3_digest_from_slice_matches_value_path() -> Result<(), JcsError> {
    let from_bytes = to_canon_blake3_digest_from_slice(br#"{"a":1,"b":[2,3]}"#)?;
    let pretty = to_canon_blake3_digest_from_slice(
        br#"{
        "b": [2, 3],
        "a": 1
    }"#,
    )?;
    assert_eq!(from_bytes, pretty);

    let via_value = to_canon_blake3_digest(&json!({"a": 1, "b": [2, 3]}))?;
    assert_eq!(from_bytes, via_value);
    Ok(())
}

#[test]
fn to_canon_blake3_digest_stable_across_calls() -> Result<(), JcsError> {
    let value = json!({"nested": {"x": 1, "y": [null, true, 2.5]}});
    let d1 = to_canon_blake3_digest(&value)?;
    let d2 = to_canon_blake3_digest(&value)?;
    assert_eq!(d1, d2);
    Ok(())
}

#[test]
fn to_canon_blake3_digest_from_slice_rejects_duplicate_keys() {
    let result = to_canon_blake3_digest_from_slice(br#"{"x": 1, "x": 2}"#);
    assert!(result.is_err(), "duplicate keys must reject");
}

#[test]
fn to_canon_blake3_digest_rejects_nonfinite_float() {
    let raw = br#"{"bad": NaN}"#;
    let via_parse = to_canon_blake3_digest_from_slice(raw);
    assert!(via_parse.is_err(), "NaN must reject through strict parse");
}

// ── Strategy-bearing digest (to_canon_digest_with) ──

#[test]
fn strategy_blake3_untagged_matches_fixed_wrapper() -> Result<(), JcsError> {
    let value = json!({"a": 1, "b": [2, 3]});
    let fixed = to_canon_blake3_digest(&value)?;
    let strategic = to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    assert_eq!(strategic.algorithm, DigestAlgorithm::Blake3Untagged);
    assert_eq!(strategic.bytes, fixed.to_vec());
    assert_eq!(strategic.algorithm.name(), "blake3-untagged");
    Ok(())
}

#[test]
fn strategy_blake3_keyed_differs_from_untagged() -> Result<(), JcsError> {
    let value = json!({"receipt_id": "abc"});
    let untagged = to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    let keyed = to_canon_digest_with(&value, &DigestStrategy::blake3_keyed([7u8; 32]))?;
    assert_ne!(
        untagged.bytes, keyed.bytes,
        "keyed must differ from untagged"
    );
    assert_eq!(keyed.algorithm.name(), "blake3-keyed");
    // Different keys produce different digests.
    let keyed_other = to_canon_digest_with(&value, &DigestStrategy::blake3_keyed([8u8; 32]))?;
    assert_ne!(
        keyed.bytes, keyed_other.bytes,
        "different keys must diverge"
    );
    Ok(())
}

#[test]
fn strategy_blake3_domain_separated_distinguishes_contexts() -> Result<(), JcsError> {
    let value = json!({"payload": 42});
    let ctx_a = to_canon_digest_with(
        &value,
        &DigestStrategy::blake3_domain_separated("vertrule.receipt.v1"),
    )?;
    let ctx_b = to_canon_digest_with(
        &value,
        &DigestStrategy::blake3_domain_separated("vertrule.policy.v1"),
    )?;
    assert_ne!(ctx_a.bytes, ctx_b.bytes, "different contexts must diverge");
    assert_eq!(ctx_a.algorithm.name(), "blake3-domain-separated");
    Ok(())
}

#[test]
fn strategy_sha256_reports_unsupported() {
    let value = json!({"x": 1});
    let result = to_canon_digest_with(&value, &DigestStrategy::sha256());
    assert!(
        matches!(result, Err(JcsError::UnsupportedAlgorithm(_))),
        "expected UnsupportedAlgorithm, got {result:?}"
    );
}

// ── canonicalize() validates strings and numbers (Candidate 4) ────

#[test]
fn canonicalize_rejects_noncharacter_in_string_value() {
    let mut v = json!({"good_key": "\u{FDD0}"});
    let result = canonicalize(&mut v);
    assert!(
        matches!(result, Err(JcsError::InvalidString(_))),
        "expected InvalidString, got {result:?}"
    );
}

#[test]
fn canonicalize_rejects_noncharacter_in_property_name() {
    let mut map = serde_json::Map::new();
    map.insert("\u{FDD0}".to_string(), json!(1));
    let mut v = Value::Object(map);
    let result = canonicalize(&mut v);
    assert!(
        matches!(result, Err(JcsError::InvalidString(_))),
        "expected InvalidString, got {result:?}"
    );
}

#[test]
fn canonicalize_rejects_non_exact_large_integer() {
    let mut v = json!({"big": 9_007_199_254_740_993u64});
    let result = canonicalize(&mut v);
    assert!(
        matches!(result, Err(JcsError::InvalidNumber(_))),
        "expected InvalidNumber, got {result:?}"
    );
}

#[test]
fn canonicalize_accepts_clean_input_unchanged() -> Result<(), JcsError> {
    let mut v = json!({"z": [{"b": 2, "a": 1}], "a": 4});
    canonicalize(&mut v)?;
    assert_eq!(canon_str(&v)?, r#"{"a":4,"z":[{"a":1,"b":2}]}"#);
    Ok(())
}

#[test]
fn canonical_digest_carries_algorithm() -> Result<(), JcsError> {
    let value = json!({"a": 1});
    let result = to_canon_digest_with(&value, &DigestStrategy::blake3_untagged())?;
    // The typed output remembers which algorithm produced it so callers
    // can record it in receipts without out-of-band convention.
    assert!(
        matches!(result.algorithm, DigestAlgorithm::Blake3Untagged),
        "expected Blake3Untagged, got {:?}",
        result.algorithm
    );
    assert_eq!(result.bytes.len(), 32);
    Ok(())
}
