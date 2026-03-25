//! # `VertRule` JCS Glovebox
//!
//! **Deterministic JSON Canonicalization (RFC 8785)**
//!
//! This crate is the single authorized location for JSON canonicalization
//! in the `VertRule` ecosystem. All receipt serialization and digest computation
//! MUST use these functions to ensure deterministic hashing.
//!
//! ## Architecture
//!
//! ```text
//! vr-jcs (canonical JSON glovebox)
//!    ↑
//!    ├── vertrule-core  (receipts, effects)
//!    └── mri2-core      (telemetry receipts)
//! ```
//!
//! ## Key Properties
//!
//! - **Lexicographic key ordering**: All object keys sorted recursively (UTF-8 byte order)
//! - **Compact encoding**: No whitespace (aligned with JCS / RFC 8785)
//! - **Deterministic**: Same logical JSON produces identical bytes across platforms
//! - **Recursive**: Nested objects are sorted at all levels
//! - **Array-preserving**: Array element order is never changed
//!
//! ## API
//!
//! - [`canonicalize`] — Sort object keys recursively in a `serde_json::Value`
//! - [`to_canon_bytes`] — Serialize any `Serialize` type to canonical JSON bytes
//! - [`to_canon_string`] — Serialize any `Serialize` type to a canonical JSON string
//!
//! ## Usage
//!
//! ```
//! use vr_jcs::to_canon_string;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct Receipt {
//!     z_field: u64,
//!     a_field: u64,
//! }
//!
//! let receipt = Receipt { z_field: 1, a_field: 2 };
//! let json = to_canon_string(&receipt).expect("serialization");
//! // Fields sorted lexicographically: a_field before z_field
//! assert_eq!(json, r#"{"a_field":2,"z_field":1}"#);
//! ```
//!
//! ## Enforcement
//!
//! Any code path that computes a digest over JSON MUST use this crate.
//! Using `serde_json::to_string()` directly for digest input is forbidden.

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(missing_docs)]

use serde::Serialize;
use serde_json::Value;

/// Error type for canonical JSON operations.
#[derive(Debug)]
pub enum JcsError {
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JCS serialization failed: {e}"),
        }
    }
}

impl std::error::Error for JcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for JcsError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Recursively sort all object keys in a JSON value for canonical representation.
///
/// This function modifies the value in place, sorting all object keys
/// lexicographically (UTF-8 byte order) and recursively processing nested
/// structures. After sorting, the value produces deterministic JSON output
/// suitable for hashing.
///
/// Array element order is preserved (arrays are ordered structures).
///
/// This implements the key-ordering requirements of JCS (RFC 8785).
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use vr_jcs::canonicalize;
///
/// let mut v = json!({"z": 1, "a": 2});
/// canonicalize(&mut v);
/// let s = serde_json::to_string(&v).expect("serialize");
/// assert_eq!(s, r#"{"a":2,"z":1}"#);
/// ```
pub fn canonicalize(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable();

            let mut sorted_pairs = Vec::with_capacity(keys.len());
            for key in keys {
                if let Some(mut value) = map.remove(&key) {
                    canonicalize(&mut value);
                    sorted_pairs.push((key, value));
                }
            }

            for (key, value) in sorted_pairs {
                map.insert(key, value);
            }
        }
        Value::Array(arr) => {
            for x in arr {
                canonicalize(x);
            }
        }
        _ => {}
    }
}

/// Serialize any `Serialize` type to canonical JSON bytes.
///
/// This is the **blessed serializer** for all receipt and digest code paths.
/// It ensures:
/// - Compact encoding (no whitespace)
/// - Sorted object keys (deterministic iteration)
/// - Platform-independent output
///
/// # Errors
///
/// Returns [`JcsError::Json`] if serialization fails.
///
/// # Examples
///
/// ```
/// use vr_jcs::to_canon_bytes;
/// use serde::Serialize;
/// use std::collections::BTreeMap;
///
/// #[derive(Serialize)]
/// struct Receipt {
///     id: u64,
///     data: BTreeMap<String, i32>,
/// }
///
/// let mut data = BTreeMap::new();
/// data.insert("zebra".to_string(), 3);
/// data.insert("apple".to_string(), 1);
///
/// let receipt = Receipt { id: 42, data };
/// let bytes = to_canon_bytes(&receipt).expect("serialize");
/// let s = String::from_utf8(bytes).expect("utf8");
/// assert_eq!(s, r#"{"data":{"apple":1,"zebra":3},"id":42}"#);
/// ```
pub fn to_canon_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    let mut json_value: Value = serde_json::to_value(value)?;
    canonicalize(&mut json_value);
    Ok(serde_json::to_vec(&json_value)?)
}

/// Serialize any `Serialize` type to a canonical JSON string.
///
/// Produces the same output as [`to_canon_bytes`] but as a UTF-8 string.
///
/// # Errors
///
/// Returns [`JcsError::Json`] if serialization fails.
///
/// # Examples
///
/// ```
/// use vr_jcs::to_canon_string;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Data {
///     z: i32,
///     a: i32,
/// }
///
/// let data = Data { z: 1, a: 2 };
/// let s = to_canon_string(&data).expect("serialize");
/// // Struct fields sorted lexicographically
/// assert_eq!(s, r#"{"a":2,"z":1}"#);
/// ```
pub fn to_canon_string<T: Serialize>(value: &T) -> Result<String, JcsError> {
    let mut json_value: Value = serde_json::to_value(value)?;
    canonicalize(&mut json_value);
    Ok(serde_json::to_string(&json_value)?)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
