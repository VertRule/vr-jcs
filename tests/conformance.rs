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

/// RFC 8785 requires ECMAScript-style number rendering.
/// These are the normative examples from the specification.
#[test]
fn rfc8785_number_zero() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(0))?, "0");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(0.0))?, "0");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(-0.0))?, "0");
    Ok(())
}

#[test]
fn rfc8785_number_integers() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(1))?, "1");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(-1))?, "-1");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(42))?, "42");
    assert_eq!(
        vr_jcs::to_canon_string(&serde_json::json!(999_999_999_999_i64))?,
        "999999999999"
    );
    Ok(())
}

#[test]
fn rfc8785_number_fractions() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(0.5))?, "0.5");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(-0.5))?, "-0.5");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(1.5))?, "1.5");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(0.1))?, "0.1");
    Ok(())
}

/// RFC 8785 §3.2.6: "If there are multiple such representations...
/// the representation with the fewest significant digits is chosen."
#[test]
fn rfc8785_shortest_representation() -> Result<(), vr_jcs::JcsError> {
    // 1e20 should render as 100000000000000000000, not 1e+20
    assert_eq!(
        vr_jcs::to_canon_string(&serde_json::json!(1e20))?,
        "100000000000000000000"
    );
    // 1e21 should use exponential: 1e+21
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(1e21))?, "1e+21");
    Ok(())
}

#[test]
fn rfc8785_exponential_notation() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(
        vr_jcs::to_canon_string(&serde_json::json!(1e100))?,
        "1e+100"
    );
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(1e-7))?, "1e-7");
    assert_eq!(
        vr_jcs::to_canon_string(&serde_json::json!(2.220_446_049_250_313e-16))?,
        "2.220446049250313e-16"
    );
    Ok(())
}

// ── RFC 8785 §3.2.3 String Serialization ──────────────────────────

#[test]
fn rfc8785_string_escaping() -> Result<(), vr_jcs::JcsError> {
    // Control characters 0x00-0x1F must be escaped
    let input = serde_json::json!({"tab": "\t", "newline": "\n", "cr": "\r"});
    let canon = vr_jcs::to_canon_string(&input)?;
    assert!(canon.contains("\\t"), "tab must be escaped: {canon}");
    assert!(canon.contains("\\n"), "newline must be escaped: {canon}");
    assert!(canon.contains("\\r"), "cr must be escaped: {canon}");
    Ok(())
}

#[test]
fn rfc8785_backslash_and_quote_escaping() -> Result<(), vr_jcs::JcsError> {
    let input = serde_json::json!({"bs": "a\\b", "qt": "a\"b"});
    let canon = vr_jcs::to_canon_string(&input)?;
    assert!(
        canon.contains("a\\\\b"),
        "backslash must be escaped: {canon}"
    );
    assert!(canon.contains("a\\\"b"), "quote must be escaped: {canon}");
    Ok(())
}

// ── RFC 8785 §3.2.4 Property Ordering ─────────────────────────────

/// RFC 8785 requires sorting by UTF-16 code units, not UTF-8 bytes.
#[test]
fn rfc8785_property_ordering_ascii() -> Result<(), vr_jcs::JcsError> {
    let canon = vr_jcs::to_canon_string(&serde_json::json!({"z": 1, "a": 2}))?;
    assert_eq!(canon, r#"{"a":2,"z":1}"#);
    Ok(())
}

#[test]
fn rfc8785_property_ordering_unicode() -> Result<(), vr_jcs::JcsError> {
    // RFC 8785 §3.2.4 example: properties sorted by UTF-16 code unit values
    let input = serde_json::json!({
        "\u{20ac}": "Euro Sign",
        "\r": "Carriage Return",
        "\u{000a}": "Newline",
        "1": "One"
    });
    let canon = vr_jcs::to_canon_string(&input)?;
    // Expected order by UTF-16 code units: \n (000A), \r (000D), "1" (0031), € (20AC)
    assert!(
        canon.find("Newline") < canon.find("Carriage Return"),
        "\\n before \\r: {canon}"
    );
    assert!(
        canon.find("Carriage Return") < canon.find("One"),
        "\\r before 1: {canon}"
    );
    assert!(
        canon.find("One") < canon.find("Euro Sign"),
        "1 before €: {canon}"
    );
    Ok(())
}

// ── RFC 8785 §3.2.5 Duplicate Property Rejection ─────────────────

#[test]
fn rfc8785_duplicate_rejection() {
    // RFC 8785 §3.2.5: "If an object contains a duplicate property
    // name, this MUST be treated as an error."
    let result = vr_jcs::to_canon_bytes_from_slice(br#"{"dup": 1, "dup": 2}"#);
    assert!(result.is_err());
}

// ── RFC 8785 §3.2.2 Literal Serialization ─────────────────────────

#[test]
fn rfc8785_literals() -> Result<(), vr_jcs::JcsError> {
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(null))?, "null");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(true))?, "true");
    assert_eq!(vr_jcs::to_canon_string(&serde_json::json!(false))?, "false");
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
    let canon = vr_jcs::to_canon_string(&input)?;
    // Verify it parses back
    let _: serde_json::Value = serde_json::from_str(&canon).map_err(vr_jcs::JcsError::from)?;
    // Verify keys are sorted
    assert!(
        canon.find("\"literals\"") < canon.find("\"numbers\""),
        "literals before numbers: {canon}"
    );
    assert!(
        canon.find("\"numbers\"") < canon.find("\"string\""),
        "numbers before string: {canon}"
    );
    Ok(())
}
