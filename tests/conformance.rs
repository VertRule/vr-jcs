//! RFC 8785 conformance tests driven by test vectors.

/// Route a `json!` value through the strict path.
fn canon(value: &serde_json::Value) -> Result<String, vr_jcs::JcsError> {
    let text = serde_json::to_string(value).map_err(vr_jcs::JcsError::from)?;
    vr_jcs::to_canon_string_from_str(&text)
}

#[test]
fn utf16_property_sorting() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({
        "\u{20ac}": "Euro",
        "\r": "CR",
        "1": "One",
        "\u{0080}": "Ctrl"
    });
    let c = canon(&input)?;
    let expected = "{\"\\r\":\"CR\",\"1\":\"One\",\"\u{0080}\":\"Ctrl\",\"\u{20ac}\":\"Euro\"}";
    assert_eq!(c, expected);
    Ok(())
}

#[test]
fn empty_structures() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str(r#"{"obj": {}, "arr": []}"#)?;
    assert_eq!(c, r#"{"arr":[],"obj":{}}"#);
    Ok(())
}

#[test]
fn nested_sorting() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str(r#"{"z": {"z": 1, "a": 2}, "a": 3}"#)?;
    assert_eq!(c, r#"{"a":3,"z":{"a":2,"z":1}}"#);
    Ok(())
}

#[test]
fn literals() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str(r"[null, true, false]")?;
    assert_eq!(c, "[null,true,false]");
    Ok(())
}

#[test]
fn integer_rendering() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str(r"[0, 1, -1, 42]")?;
    assert_eq!(c, "[0,1,-1,42]");
    Ok(())
}

#[test]
fn negative_zero_renders_as_zero() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str("[-0.0]")?;
    assert_eq!(c, "[0]");
    Ok(())
}

// ── Rejection vectors ──────────────────────────────────────────────

#[test]
fn reject_duplicate_keys() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"a": 1, "a": 2}"#);
    assert!(result.is_err());
    assert!(result
        .err()
        .is_some_and(|e| e.to_string().contains("duplicate property name")));
}

#[test]
fn reject_nested_duplicate_keys() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"outer": {"a": 1, "a": 2}}"#);
    assert!(result.is_err());
    assert!(result
        .err()
        .is_some_and(|e| e.to_string().contains("duplicate property name")));
}

#[test]
fn reject_noncharacter_u_fdd0() {
    let result = vr_jcs::to_canon_string_from_str("{\"bad\":\"\u{fdd0}\"}");
    assert!(result.is_err());
    assert!(result
        .err()
        .is_some_and(|e| e.to_string().contains("forbidden noncharacter")));
}

// ── RFC 8785 §3.2.6 Number Serialization Test Vectors ─────────────

#[test]
fn rfc8785_number_zero() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string_from_str("0")?, "0");
    assert_eq!(vr_jcs::to_canon_string_from_str("0.0")?, "0");
    assert_eq!(vr_jcs::to_canon_string_from_str("-0.0")?, "0");
    Ok(())
}

#[test]
fn rfc8785_number_integers() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string_from_str("1")?, "1");
    assert_eq!(vr_jcs::to_canon_string_from_str("-1")?, "-1");
    assert_eq!(vr_jcs::to_canon_string_from_str("42")?, "42");
    assert_eq!(
        vr_jcs::to_canon_string_from_str("999999999999")?,
        "999999999999"
    );
    Ok(())
}

#[test]
fn rfc8785_number_fractions() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string_from_str("0.5")?, "0.5");
    assert_eq!(vr_jcs::to_canon_string_from_str("-0.5")?, "-0.5");
    assert_eq!(vr_jcs::to_canon_string_from_str("1.5")?, "1.5");
    assert_eq!(vr_jcs::to_canon_string_from_str("0.1")?, "0.1");
    Ok(())
}

/// RFC 8785 §3.2.6: "If there are multiple such representations...
/// the representation with the fewest significant digits is chosen."
#[test]
fn rfc8785_shortest_representation() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(
        vr_jcs::to_canon_string_from_str("1e20")?,
        "100000000000000000000"
    );
    assert_eq!(vr_jcs::to_canon_string_from_str("1e21")?, "1e+21");
    Ok(())
}

#[test]
fn rfc8785_exponential_notation() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string_from_str("1e100")?, "1e+100");
    assert_eq!(vr_jcs::to_canon_string_from_str("1e-7")?, "1e-7");
    assert_eq!(
        vr_jcs::to_canon_string_from_str("2.220446049250313e-16")?,
        "2.220446049250313e-16"
    );
    Ok(())
}

// ── RFC 8785 §3.2.3 String Serialization ──────────────────────────

#[test]
fn rfc8785_string_escaping() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({"tab": "\t", "newline": "\n", "cr": "\r"});
    let c = canon(&input)?;
    assert!(c.contains("\\t"), "tab must be escaped: {c}");
    assert!(c.contains("\\n"), "newline must be escaped: {c}");
    assert!(c.contains("\\r"), "cr must be escaped: {c}");
    Ok(())
}

#[test]
fn rfc8785_backslash_and_quote_escaping() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({"bs": "a\\b", "qt": "a\"b"});
    let c = canon(&input)?;
    assert!(c.contains("a\\\\b"), "backslash must be escaped: {c}");
    assert!(c.contains("a\\\"b"), "quote must be escaped: {c}");
    Ok(())
}

// ── RFC 8785 §3.2.4 Property Ordering ─────────────────────────────

#[test]
fn rfc8785_property_ordering_ascii() -> Result<(), vr_jcs::JcsError> {
    let c = vr_jcs::to_canon_string_from_str(r#"{"z": 1, "a": 2}"#)?;
    assert_eq!(c, r#"{"a":2,"z":1}"#);
    Ok(())
}

#[test]
fn rfc8785_property_ordering_unicode() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "\u{000a}": "Newline",
        "1": "One"
    });
    let c = canon(&input)?;
    assert!(
        c.find("Newline") < c.find("Carriage Return"),
        "\\n before \\r: {c}"
    );
    assert!(
        c.find("Carriage Return") < c.find("One"),
        "\\r before 1: {c}"
    );
    assert!(c.find("One") < c.find("Euro Sign"), "1 before ���: {c}");
    Ok(())
}

// ── RFC 8785 §3.2.5 Duplicate Property Rejection ─────────────────

#[test]
fn rfc8785_duplicate_rejection() {
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"dup": 1, "dup": 2}"#);
    assert!(result.is_err());
}

// ── RFC 8785 §3.2.2 Literal Serialization ─────────────────────────

#[test]
fn rfc8785_literals() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string_from_str("null")?, "null");
    assert_eq!(vr_jcs::to_canon_string_from_str("true")?, "true");
    assert_eq!(vr_jcs::to_canon_string_from_str("false")?, "false");
    Ok(())
}

// ── Composite: RFC 8785 §3.2.7 Full Example ───────────────────────

#[test]
#[allow(clippy::excessive_precision)]
fn rfc8785_composite_example() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({
        "numbers": [333_333_333.333_333_29, 1e30, 4.50, 2e-3, 0.000_000_000_000_000_000_000_000_001],
        "string": "\u{20ac}$\u{000f}\u{000a}A'\u{0042}\\\\\"/",
        "literals": [null, true, false]
    });
    let c = canon(&input)?;
    let _: serde_json::Value = serde_json::from_str(&c).map_err(vr_jcs::JcsError::from)?;
    assert!(
        c.find("\"literals\"") < c.find("\"numbers\""),
        "literals before numbers: {c}"
    );
    assert!(
        c.find("\"numbers\"") < c.find("\"string\""),
        "numbers before string: {c}"
    );
    Ok(())
}
