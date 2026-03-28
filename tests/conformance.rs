//! RFC 8785 conformance tests driven by test vectors.

#[test]
fn utf16_property_sorting() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({
        "\u{20ac}": "Euro",
        "\r": "CR",
        "1": "One",
        "\u{0080}": "Ctrl"
    });
    let canon = vr_jcs::to_canon_string(&input)?;
    let expected = "{\"\\r\":\"CR\",\"1\":\"One\",\"\u{0080}\":\"Ctrl\",\"\u{20ac}\":\"Euro\"}";
    assert_eq!(canon, expected);
    Ok(())
}

#[test]
fn empty_structures() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({"obj": {}, "arr": []});
    let canon = vr_jcs::to_canon_string(&input)?;
    assert_eq!(canon, "{\"arr\":[],\"obj\":{}}");
    Ok(())
}

#[test]
fn nested_sorting() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({"z": {"z": 1, "a": 2}, "a": 3});
    let canon = vr_jcs::to_canon_string(&input)?;
    assert_eq!(canon, "{\"a\":3,\"z\":{\"a\":2,\"z\":1}}");
    Ok(())
}

#[test]
fn literals() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!([null, true, false]);
    let canon = vr_jcs::to_canon_string(&input)?;
    assert_eq!(canon, "[null,true,false]");
    Ok(())
}

#[test]
fn integer_rendering() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!([0, 1, -1, 42]);
    let canon = vr_jcs::to_canon_string(&input)?;
    assert_eq!(canon, "[0,1,-1,42]");
    Ok(())
}

#[test]
fn negative_zero_renders_as_zero() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&serde_json::json!([-0.0]))?;
    assert_eq!(canon, "[0]");
    Ok(())
}

// ── Rejection vectors ──────────────────────────────────────────────

#[test]
fn reject_duplicate_keys() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"a": 1, "a": 2}"#);
    assert!(result.is_err());
    assert!(result.err().is_some_and(|e| e.to_string().contains("duplicate property name")));
}

#[test]
fn reject_nested_duplicate_keys() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"outer": {"a": 1, "a": 2}}"#);
    assert!(result.is_err());
    assert!(result.err().is_some_and(|e| e.to_string().contains("duplicate property name")));
}

#[test]
fn reject_noncharacter_u_fdd0() {
    let result = vr_jcs::to_canon_string_from_str("{\"bad\":\"\u{fdd0}\"}");
    assert!(result.is_err());
    assert!(result.err().is_some_and(|e| e.to_string().contains("forbidden noncharacter")));
}
