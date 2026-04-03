//! # vr-jcs
//!
//! RFC 8785 JSON Canonicalization Scheme (JCS) for Rust.
//!
//! Produces canonical JSON suitable for deterministic digest computation,
//! content hashing, and stable serialization boundaries. Implements the
//! RFC 8785 rules that materially affect wire compatibility:
//! - UTF-16 code-unit sorting for object property names
//! - ECMAScript-compatible primitive serialization
//! - UTF-8 output without insignificant whitespace
//! - duplicate-property rejection on raw JSON parse paths
//! - I-JSON string / number validation
//!
//! ## API
//!
//! ### Strict path (for untrusted JSON)
//!
//! - [`to_canon_bytes_from_slice`] — Parse untrusted JSON, apply strict admission checks, emit canonical bytes
//! - [`to_canon_string_from_str`] — Parse untrusted JSON string, apply strict admission checks, emit canonical string
//!
//! ### Typed path (caller-controlled construction only, deprecated)
//!
//! - [`to_canon_bytes`] — Serialize any `Serialize` type to canonical JSON bytes
//! - [`to_canon_string`] — Serialize any `Serialize` type to a canonical JSON string
//!
//! ### In-place
//!
//! - [`canonicalize`] — Sort object keys recursively in a `serde_json::Value`
//!
//! ## Usage
//!
//! ```
//! # fn main() -> Result<(), vr_jcs::JcsError> {
//! let json = vr_jcs::to_canon_string_from_str(r#"{"z_field":1,"a_field":2}"#)?;
//! assert_eq!(json, r#"{"a_field":2,"z_field":1}"#);
//! # Ok(())
//! # }
//! ```

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::de::{self, DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use serde_json::{Number, Value};

/// Maximum permitted nesting depth for JSON structures.
///
/// Set to 128: 25x headroom over the deepest observed receipt artifacts
/// in the `VertRule` ecosystem (5 levels) and aligned with `serde_json`'s
/// default recursion limit. Applies uniformly to strict parse,
/// in-place canonicalization, and recursive emission.
pub const MAX_NESTING_DEPTH: usize = 128;

/// Error type for canonical JSON operations.
#[derive(Debug)]
pub enum JcsError {
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// A JSON string violated I-JSON constraints.
    InvalidString(String),
    /// A JSON number violated JCS / I-JSON constraints.
    InvalidNumber(String),
    /// The input exceeded [`MAX_NESTING_DEPTH`].
    NestingDepthExceeded,
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JCS JSON processing failed: {e}"),
            Self::InvalidString(msg) => write!(f, "JCS string validation failed: {msg}"),
            Self::InvalidNumber(msg) => write!(f, "JCS number validation failed: {msg}"),
            Self::NestingDepthExceeded => write!(
                f,
                "JCS nesting depth exceeded maximum of {MAX_NESTING_DEPTH}"
            ),
        }
    }
}

impl std::error::Error for JcsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::InvalidString(_) | Self::InvalidNumber(_) | Self::NestingDepthExceeded => None,
        }
    }
}

impl From<serde_json::Error> for JcsError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Serialize any `Serialize` type to canonical JSON bytes.
///
/// The typed `Serialize` path is not authoritative for untrusted raw JSON
/// because it does not control parse-time object-member admission. For
/// untrusted input, use [`to_canon_bytes_from_slice`] instead.
///
/// # Errors
///
/// Returns:
/// - [`JcsError::Json`] if serialization to JSON fails
/// - [`JcsError::InvalidString`] if a string contains an I-JSON forbidden code point
/// - [`JcsError::InvalidNumber`] if a number is not interoperable under JCS
/// - [`JcsError::NestingDepthExceeded`] if the value exceeds [`MAX_NESTING_DEPTH`]
#[deprecated(
    since = "0.3.0",
    note = "use to_canon_bytes_from_slice for untrusted input; see PUBLIC_SURFACE.md"
)]
pub fn to_canon_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError> {
    let value = serde_json::to_value(value)?;
    to_canon_bytes_value(&value)
}

/// Serialize any `Serialize` type to a canonical JSON string.
///
/// # Errors
///
/// Returns the same errors as [`to_canon_bytes_from_slice`].
#[deprecated(
    since = "0.3.0",
    note = "use to_canon_string_from_str for untrusted input; see PUBLIC_SURFACE.md"
)]
pub fn to_canon_string<T: Serialize>(value: &T) -> Result<String, JcsError> {
    let value = serde_json::to_value(value)?;
    let bytes = to_canon_bytes_value(&value)?;
    String::from_utf8(bytes).map_err(|error| {
        JcsError::InvalidString(format!(
            "canonical JSON output was not valid UTF-8: {error}"
        ))
    })
}

/// Parse untrusted JSON, apply strict admission checks, and emit canonical
/// RFC 8785 bytes.
///
/// Rejects duplicate property names, validates I-JSON string and number
/// constraints, and enforces [`MAX_NESTING_DEPTH`]. Accepts any valid JSON
/// formatting (including pretty-printed input) and canonicalizes it.
///
/// # Errors
///
/// Returns [`JcsError::Json`] for malformed JSON or duplicate property names,
/// [`JcsError::InvalidString`] or [`JcsError::InvalidNumber`] for I-JSON
/// violations, and [`JcsError::NestingDepthExceeded`] for depth limit breach.
pub fn to_canon_bytes_from_slice(json: &[u8]) -> Result<Vec<u8>, JcsError> {
    let value = parse_json_value_no_duplicates(json)?;
    to_canon_bytes_value(&value)
}

/// Parse untrusted JSON text, apply strict admission checks, and emit a
/// canonical RFC 8785 string.
///
/// # Errors
///
/// Returns the same errors as [`to_canon_bytes_from_slice`].
pub fn to_canon_string_from_str(json: &str) -> Result<String, JcsError> {
    let bytes = to_canon_bytes_from_slice(json.as_bytes())?;
    String::from_utf8(bytes).map_err(|error| {
        JcsError::InvalidString(format!(
            "canonical JSON output was not valid UTF-8: {error}"
        ))
    })
}

/// Recursively sort all object keys in a JSON value for canonical representation.
///
/// This function modifies the value in place, sorting all object keys
/// by UTF-16 code units (RFC 8785) and recursively processing nested
/// structures. Array element order is preserved.
///
/// For digest computation, prefer [`to_canon_bytes_from_slice`] which
/// handles the full strict parse + canonical emit pipeline.
///
/// # Errors
///
/// Returns [`JcsError::NestingDepthExceeded`] if the value exceeds
/// [`MAX_NESTING_DEPTH`].
pub fn canonicalize(v: &mut Value) -> Result<(), JcsError> {
    canonicalize_depth(v, 0)
}

fn canonicalize_depth(v: &mut Value, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(JcsError::NestingDepthExceeded);
    }
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut entries: Vec<(String, Value)> = keys
                .into_iter()
                .filter_map(|k| map.remove(&k).map(|v| (k, v)))
                .collect();
            entries.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
            for (key, mut value) in entries {
                canonicalize_depth(&mut value, depth + 1)?;
                map.insert(key, value);
            }
        }
        Value::Array(arr) => {
            for x in arr {
                canonicalize_depth(x, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ── Provisional helpers for sibling crates ─────────────────────────
//
// Not part of the stable v0.3 API. Subject to change or removal
// without semver bump. If still needed at publish time, these will
// be gated behind `feature = "unstable"`.

/// Deserialize a JSON value while rejecting duplicate property names.
///
/// Used by `vertrule-schemas` for ingestion validation.
///
/// # Errors
///
/// Returns an error if the input contains duplicate property names,
/// forbidden noncharacters, or is otherwise invalid JSON.
#[doc(hidden)]
pub fn deserialize_json_value_no_duplicates<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    NoDuplicateValueSeed { depth: 0 }.deserialize(deserializer)
}

/// Validate that a string contains no I-JSON forbidden noncharacters.
///
/// # Errors
///
/// Returns a description of the violation if the string contains a
/// forbidden Unicode noncharacter (U+FDD0..U+FDEF, U+xFFFE, U+xFFFF).
#[doc(hidden)]
pub fn validate_string_contents(value: &str, context: &str) -> Result<(), String> {
    if let Some(ch) = value.chars().find(|&ch| is_noncharacter(ch)) {
        return Err(format!(
            "{context} contains the forbidden noncharacter U+{:04X}",
            ch as u32
        ));
    }
    Ok(())
}

/// Check if an integer is in the I-JSON safe integer range `[-2^53+1, 2^53-1]`.
#[doc(hidden)]
#[must_use]
pub fn is_safe_integer(value: i64) -> bool {
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)
}

// ── Internal implementation ────────────────────────────────────────

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn to_canon_bytes_value(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    emit_value(&mut out, value, 0)?;
    Ok(out)
}

fn emit_value(out: &mut Vec<u8>, value: &Value, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(JcsError::NestingDepthExceeded);
    }
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(boolean) => {
            if *boolean {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
        }
        Value::Number(number) => emit_number(out, number)?,
        Value::String(string) => emit_string(out, string, "string value")?,
        Value::Array(array) => {
            out.push(b'[');
            for (index, item) in array.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                emit_value(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            out.push(b'{');
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| cmp_utf16(left, right));

            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                emit_string(out, key, "object property name")?;
                out.push(b':');
                emit_value(out, item, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn emit_number(out: &mut Vec<u8>, number: &Number) -> Result<(), JcsError> {
    if let Some(value) = number.as_i64() {
        ensure_exact_binary64_integer(value.unsigned_abs(), &value.to_string())?;
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }

    if let Some(value) = number.as_u64() {
        ensure_exact_binary64_integer(value, &value.to_string())?;
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }

    if let Some(value) = number.as_f64() {
        if !value.is_finite() {
            return Err(JcsError::InvalidNumber(
                "encountered a non-finite floating-point number".to_string(),
            ));
        }

        let rendered = format_ecmascript_number(value)?;
        out.extend_from_slice(rendered.as_bytes());
        return Ok(());
    }

    Err(JcsError::InvalidNumber(
        "unsupported JSON number representation".to_string(),
    ))
}

fn emit_string(out: &mut Vec<u8>, value: &str, context: &str) -> Result<(), JcsError> {
    validate_string_contents(value, context).map_err(JcsError::InvalidString)?;

    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br"\\"),
            '\u{0008}' => out.extend_from_slice(br"\b"),
            '\u{0009}' => out.extend_from_slice(br"\t"),
            '\u{000A}' => out.extend_from_slice(br"\n"),
            '\u{000C}' => out.extend_from_slice(br"\f"),
            '\u{000D}' => out.extend_from_slice(br"\r"),
            '\u{0000}'..='\u{001F}' => {
                let escaped = format!(r"\u{:04x}", ch as u32);
                out.extend_from_slice(escaped.as_bytes());
            }
            _ => {
                let mut buf = [0u8; 4];
                let encoded = ch.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');

    Ok(())
}

fn ensure_exact_binary64_integer(value: u64, original: &str) -> Result<(), JcsError> {
    if is_exact_binary64_integer(value) {
        Ok(())
    } else {
        Err(JcsError::InvalidNumber(format!(
            "integer {original} is not exactly representable as an IEEE 754 double; encode it as a string"
        )))
    }
}

const fn is_exact_binary64_integer(value: u64) -> bool {
    if value == 0 {
        return true;
    }
    let bit_len = u64::BITS - value.leading_zeros();
    bit_len <= 53 || value.trailing_zeros() >= bit_len - 53
}

fn format_ecmascript_number(value: f64) -> Result<String, JcsError> {
    if value == 0.0 {
        return Ok("0".to_string());
    }

    let mut buffer = zmij::Buffer::new();
    let shortest = buffer.format_finite(value);
    let (negative, body) = if let Some(stripped) = shortest.strip_prefix('-') {
        (true, stripped)
    } else {
        (false, shortest)
    };

    let (digits, exponent) = parse_shortest_decimal(body)?;
    let rendered = render_ecmascript_number(&digits, exponent)?;

    if negative {
        Ok(format!("-{rendered}"))
    } else {
        Ok(rendered)
    }
}

fn parse_shortest_decimal(body: &str) -> Result<(String, i32), JcsError> {
    if let Some((mantissa, exponent)) = body.split_once('e') {
        let digits: String = mantissa.chars().filter(|&ch| ch != '.').collect();
        let exponent = exponent.parse::<i32>().map_err(|error| {
            JcsError::InvalidNumber(format!(
                "failed to parse formatter exponent {exponent:?}: {error}"
            ))
        })?;
        return Ok((digits, exponent + 1));
    }

    if let Some((integer, fractional)) = body.split_once('.') {
        let fractional = fractional.trim_end_matches('0');

        if integer != "0" {
            let mut digits = String::with_capacity(integer.len() + fractional.len());
            digits.push_str(integer);
            digits.push_str(fractional);
            let exponent = i32::try_from(integer.len()).map_err(|_| {
                JcsError::InvalidNumber(
                    "formatter emitted an unexpectedly large integer part".to_string(),
                )
            })?;
            return Ok((digits, exponent));
        }

        let leading_zeros = fractional.bytes().take_while(|&byte| byte == b'0').count();
        let exponent = i32::try_from(leading_zeros).map_err(|_| {
            JcsError::InvalidNumber(
                "formatter emitted an unexpectedly long leading-zero run".to_string(),
            )
        })?;
        return Ok((fractional[leading_zeros..].to_owned(), -exponent));
    }

    let exponent = i32::try_from(body.len()).map_err(|_| {
        JcsError::InvalidNumber("formatter emitted an unexpectedly long integer".to_string())
    })?;
    Ok((body.to_owned(), exponent))
}

fn render_ecmascript_number(digits: &str, exponent: i32) -> Result<String, JcsError> {
    let digits_len = i32::try_from(digits.len()).map_err(|_| {
        JcsError::InvalidNumber("formatter emitted an unexpectedly long digit sequence".to_string())
    })?;
    if digits_len == 0 {
        return Err(JcsError::InvalidNumber("empty digit sequence".to_string()));
    }

    if digits_len <= exponent && exponent <= 21 {
        let capacity = usize::try_from(exponent).map_err(|_| {
            JcsError::InvalidNumber(
                "formatter produced a negative fixed-width exponent".to_string(),
            )
        })?;
        let mut out = String::with_capacity(capacity);
        out.push_str(digits);
        for _ in 0..(exponent - digits_len) {
            out.push('0');
        }
        return Ok(out);
    }

    if 0 < exponent && exponent <= 21 {
        let split = usize::try_from(exponent).map_err(|_| {
            JcsError::InvalidNumber("formatter produced a negative split exponent".to_string())
        })?;
        let mut out = String::with_capacity(digits.len() + 1);
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
        return Ok(out);
    }

    if -6 < exponent && exponent <= 0 {
        let zeros = usize::try_from(-exponent).map_err(|_| {
            JcsError::InvalidNumber("formatter produced an invalid negative exponent".to_string())
        })?;
        let mut out = String::with_capacity(2 + zeros + digits.len());
        out.push_str("0.");
        for _ in 0..zeros {
            out.push('0');
        }
        out.push_str(digits);
        return Ok(out);
    }

    let exponent = exponent - 1;
    let (first, rest) = digits.split_at(1);
    let mut out = String::with_capacity(digits.len() + 6);
    out.push_str(first);
    if !rest.is_empty() {
        out.push('.');
        out.push_str(rest);
    }
    out.push('e');
    if exponent >= 0 {
        out.push('+');
    }
    out.push_str(&exponent.to_string());
    Ok(out)
}

fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn is_noncharacter(ch: char) -> bool {
    let code = ch as u32;
    (0xFDD0..=0xFDEF).contains(&code) || (code <= 0x0010_FFFF && code & 0xFFFE == 0xFFFE)
}

/// Sentinel prefix used by `NoDuplicateValueSeed` to signal depth exceeded
/// through serde's error channel. Matched in `parse_json_value_no_duplicates`
/// to promote the error to `JcsError::NestingDepthExceeded`.
const DEPTH_EXCEEDED_SENTINEL: &str = "nesting depth exceeded maximum of ";

fn parse_json_value_no_duplicates(json: &[u8]) -> Result<Value, JcsError> {
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    // Disable serde_json's built-in recursion limit — we enforce
    // MAX_NESTING_DEPTH via NoDuplicateValueSeed instead.
    deserializer.disable_recursion_limit();
    let value = deserialize_json_value_no_duplicates(&mut deserializer).map_err(|e| {
        if e.to_string().starts_with(DEPTH_EXCEEDED_SENTINEL) {
            JcsError::NestingDepthExceeded
        } else {
            JcsError::Json(e)
        }
    })?;
    deserializer.end()?;
    Ok(value)
}

struct NoDuplicateValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for NoDuplicateValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_NESTING_DEPTH {
            return Err(D::Error::custom(format!(
                "{DEPTH_EXCEEDED_SENTINEL}{MAX_NESTING_DEPTH}"
            )));
        }
        deserializer.deserialize_any(NoDuplicateValueVisitor { depth: self.depth })
    }
}

struct NoDuplicateValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for NoDuplicateValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("encountered a non-finite floating-point number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        validate_string_contents(value, "string value").map_err(E::custom)?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        validate_string_contents(&value, "string value").map_err(E::custom)?;
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));
        while let Some(value) = access.next_element_seed(NoDuplicateValueSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let Some(first_key) = access.next_key::<String>()? else {
            return Ok(Value::Object(serde_json::Map::new()));
        };

        // Validate first key (skip internal '$'-prefixed keys used by
        // serde_json for number representations under arbitrary_precision).
        if !first_key.starts_with('$') {
            validate_string_contents(&first_key, "object property name")
                .map_err(A::Error::custom)?;
        }

        let first_value = access.next_value_seed(NoDuplicateValueSeed {
            depth: self.depth + 1,
        })?;

        let mut object = serde_json::Map::new();
        object.insert(first_key.clone(), first_value);

        let mut seen = BTreeSet::new();
        seen.insert(first_key);

        while let Some(key) = access.next_key::<String>()? {
            // Only validate user-facing keys (skip internal serde keys
            // that start with '$'). This handles arbitrary_precision
            // numbers without depending on private serde_json internals.
            if !key.starts_with('$') {
                validate_string_contents(&key, "object property name").map_err(A::Error::custom)?;
            }

            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate property name `{key}`")));
            }

            let value = access.next_value_seed(NoDuplicateValueSeed {
                depth: self.depth + 1,
            })?;
            object.insert(key, value);
        }

        // If the map is a serde_json internal number representation,
        // serde_json::from_value will reconstruct the proper Number.
        // For real JSON objects, this is a no-op identity conversion.
        serde_json::from_value(Value::Object(object)).map_err(A::Error::custom)
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
