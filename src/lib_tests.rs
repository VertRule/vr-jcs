use super::*;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn canonicalize_flat_object() -> Result<(), JcsError> {
    let mut v = json!({"z": 1, "a": 2, "m": 3});
    canonicalize(&mut v);

    let s = serde_json::to_string(&v)?;
    assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    Ok(())
}

#[test]
fn canonicalize_nested_objects() -> Result<(), JcsError> {
    let mut v = json!({
        "outer_z": {"inner_z": 1, "inner_a": 2},
        "outer_a": {"inner_z": 3, "inner_a": 4}
    });
    canonicalize(&mut v);

    let s = serde_json::to_string(&v)?;
    assert_eq!(
        s,
        r#"{"outer_a":{"inner_a":4,"inner_z":3},"outer_z":{"inner_a":2,"inner_z":1}}"#
    );
    Ok(())
}

#[test]
fn canonicalize_preserves_array_order() -> Result<(), JcsError> {
    let mut v = json!({
        "z": [{"b": 2, "a": 1}],
        "a": [{"b": 4, "a": 3}]
    });
    canonicalize(&mut v);

    let s = serde_json::to_string(&v)?;
    assert_eq!(s, r#"{"a":[{"a":3,"b":4}],"z":[{"a":1,"b":2}]}"#);
    Ok(())
}

#[test]
fn canonicalize_empty_object() -> Result<(), JcsError> {
    let mut v = json!({});
    canonicalize(&mut v);

    let s = serde_json::to_string(&v)?;
    assert_eq!(s, "{}");
    Ok(())
}

#[test]
fn canonicalize_scalar_is_noop() {
    let mut v = json!(42);
    canonicalize(&mut v);
    assert_eq!(v, json!(42));

    let mut v = json!("hello");
    canonicalize(&mut v);
    assert_eq!(v, json!("hello"));

    let mut v = json!(null);
    canonicalize(&mut v);
    assert_eq!(v, json!(null));

    let mut v = json!(true);
    canonicalize(&mut v);
    assert_eq!(v, json!(true));
}

#[test]
fn to_canon_bytes_struct() -> Result<(), JcsError> {
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

    let bytes = to_canon_bytes(&receipt)?;
    let s = String::from_utf8(bytes).map_err(|_| {
        JcsError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "utf8",
        )))
    })?;

    assert_eq!(s, r#"{"data":{"apple":1,"mango":2,"zebra":3},"id":42}"#);
    Ok(())
}

#[test]
fn to_canon_string_deterministic() -> Result<(), JcsError> {
    #[derive(Serialize)]
    struct Data {
        z: i32,
        a: i32,
    }

    let data = Data { z: 1, a: 2 };

    let s1 = to_canon_string(&data)?;
    let s2 = to_canon_string(&data)?;

    assert_eq!(s1, s2);
    assert_eq!(s1, r#"{"a":2,"z":1}"#);
    Ok(())
}

#[test]
#[allow(
    clippy::unreadable_literal,
    reason = "Test values are intentionally unformatted for copy-paste accuracy"
)]
fn shuffle_invariant_bytes() -> Result<(), JcsError> {
    let v1 = json!({
        "id": 123,
        "timestamp": 456789,
        "data": {"x": 1, "y": 2, "z": 3},
        "tags": ["a", "b", "c"]
    });

    let v2 = json!({
        "tags": ["a", "b", "c"],
        "data": {"z": 3, "x": 1, "y": 2},
        "timestamp": 456789,
        "id": 123
    });

    let bytes1 = to_canon_bytes(&v1)?;
    let bytes2 = to_canon_bytes(&v2)?;

    assert_eq!(bytes1, bytes2);
    Ok(())
}

#[test]
fn shuffle_invariant_hashing() -> Result<(), JcsError> {
    let v1 = json!({"z": 1, "a": 2});
    let v2 = json!({"a": 2, "z": 1});

    let bytes1 = to_canon_bytes(&v1)?;
    let bytes2 = to_canon_bytes(&v2)?;

    let hash1 = blake3::hash(&bytes1);
    let hash2 = blake3::hash(&bytes2);

    assert_eq!(hash1, hash2);
    Ok(())
}

#[test]
fn canon_bytes_equals_canon_string_bytes() -> Result<(), JcsError> {
    let v = json!({"a": 1, "b": 2});

    let bytes = to_canon_bytes(&v)?;
    let string = to_canon_string(&v)?;

    assert_eq!(bytes, string.as_bytes());
    Ok(())
}

#[test]
fn deeply_nested_canonicalization() -> Result<(), JcsError> {
    let mut v = json!({
        "z": {
            "z": {
                "z": 1,
                "a": 2
            },
            "a": 3
        },
        "a": 4
    });
    canonicalize(&mut v);

    let s = serde_json::to_string(&v)?;
    assert_eq!(s, r#"{"a":4,"z":{"a":3,"z":{"a":2,"z":1}}}"#);
    Ok(())
}

#[test]
fn mixed_types_in_object() -> Result<(), JcsError> {
    let s = to_canon_string(&json!({
        "z_bool": true,
        "a_null": null,
        "m_num": 42,
        "b_str": "hello",
        "c_arr": [1, 2, 3]
    }))?;

    assert_eq!(
        s,
        r#"{"a_null":null,"b_str":"hello","c_arr":[1,2,3],"m_num":42,"z_bool":true}"#
    );
    Ok(())
}

#[test]
fn jcs_error_display() {
    let err = JcsError::Json(serde_json::Error::io(std::io::Error::other("test error")));
    let msg = err.to_string();
    assert!(msg.contains("JCS serialization failed"));
}
