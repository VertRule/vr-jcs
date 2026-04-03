//! Compatibility tests for the deprecated typed `Serialize` path.
//!
//! Validates that `to_canon_bytes<T>` and `to_canon_string<T>` remain
//! functional during migration. Remove this file when the shim
//! removal condition in the Shim Policy is met.

#![allow(deprecated)]

use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn struct_serialization() -> Result<(), vr_jcs::JcsError> {
    #[derive(Serialize)]
    struct Receipt {
        id: u64,
        data: BTreeMap<String, i32>,
    }

    let mut data = BTreeMap::new();
    data.insert("zebra".to_string(), 3);
    data.insert("apple".to_string(), 1);
    data.insert("mango".to_string(), 2);

    let receipt = Receipt { id: 42, data };
    let bytes = vr_jcs::to_canon_bytes(&receipt)?;
    let string =
        String::from_utf8(bytes).map_err(|e| vr_jcs::JcsError::InvalidString(e.to_string()))?;

    assert_eq!(
        string,
        r#"{"data":{"apple":1,"mango":2,"zebra":3},"id":42}"#
    );
    Ok(())
}

#[test]
fn typed_bytes_equals_typed_string_bytes() -> Result<(), vr_jcs::JcsError> {
    let value = json!({"a": 1, "b": 2});
    let bytes = vr_jcs::to_canon_bytes(&value)?;
    let string = vr_jcs::to_canon_string(&value)?;
    assert_eq!(bytes, string.as_bytes());
    Ok(())
}

#[test]
fn typed_path_agrees_with_strict_on_admitted_input() -> Result<(), vr_jcs::JcsError> {
    let inputs = [
        r#"{"a":1,"b":2}"#,
        r#"{"a":{"b":{"c":3}}}"#,
        r"[1,2,3]",
        r#"{"arr":[1,null,true],"nested":{"x":"y"},"z":0}"#,
        r"null",
        r"true",
        r"42",
        r#""hello""#,
        r"[0,1,-1,0.5,1e+21]",
    ];

    for input in inputs {
        let strict = vr_jcs::to_canon_bytes_from_slice(input.as_bytes())?;
        let value: serde_json::Value =
            serde_json::from_str(input).map_err(vr_jcs::JcsError::from)?;
        let typed = vr_jcs::to_canon_bytes(&value)?;
        assert_eq!(strict, typed, "paths disagree on: {input}");
    }
    Ok(())
}
