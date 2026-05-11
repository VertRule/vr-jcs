//! RFC 8785 canonical emit and in-place key sorting.
//!
//! [`to_canon_bytes_value`] is the trusted-`Value` emit pipeline used
//! internally by every public emit/digest entry point. It enforces
//! UTF-16 code-unit key ordering, ECMAScript-compatible primitive
//! serialization (delegated to [`crate::number`]), I-JSON string
//! validation (delegated to [`crate::strict_parse`]), and
//! [`crate::MAX_NESTING_DEPTH`].
//!
//! [`canonicalize`] is the in-place sibling for callers that hold a
//! `serde_json::Value` and want it canonically shaped before further
//! processing. It validates the same I-JSON invariants that
//! [`to_canon_bytes_value`] enforces — strings against the
//! noncharacter set, numbers against the IEEE 754 binary64 exactness
//! and finite-float rules — so a `Value` that survives `canonicalize`
//! will round-trip through the emit pipeline identically.

use std::cmp::Ordering;

use serde_json::Value;

use crate::error::JcsError;
use crate::number;
use crate::strict_parse;
use crate::MAX_NESTING_DEPTH;

/// Emit a trusted [`Value`] as canonical RFC 8785 bytes.
pub(crate) fn to_canon_bytes_value(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::new();
    emit_value(&mut out, value, 0)?;
    Ok(out)
}

/// Recursively sort all object keys in a JSON value for canonical
/// representation.
///
/// Modifies `v` in place: object keys are sorted by UTF-16 code units
/// (RFC 8785), and nested structures are processed recursively. Array
/// element order is preserved.
///
/// In addition to sorting, `canonicalize` validates strings against
/// I-JSON forbidden noncharacters and numbers against IEEE 754 binary64
/// exactness and finite-float rules. A `Value` that survives this
/// function will round-trip identically through
/// [`to_canon_bytes_value`].
///
/// For digest computation, prefer [`crate::to_canon_bytes_from_slice`]
/// which handles the full strict parse + canonical emit pipeline over
/// untrusted input.
///
/// # Errors
///
/// Returns:
/// - [`JcsError::NestingDepthExceeded`] if the value exceeds [`MAX_NESTING_DEPTH`].
/// - [`JcsError::InvalidString`] if a string or property name contains
///   a forbidden Unicode noncharacter.
/// - [`JcsError::InvalidNumber`] if a number is non-finite or not
///   exactly representable as an IEEE 754 double.
pub fn canonicalize(v: &mut Value) -> Result<(), JcsError> {
    canonicalize_depth(v, 0)
}

fn canonicalize_depth(v: &mut Value, depth: usize) -> Result<(), JcsError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(JcsError::NestingDepthExceeded);
    }
    match v {
        Value::Object(map) => {
            for key in map.keys() {
                strict_parse::validate_string_contents(key, "object property name")
                    .map_err(JcsError::InvalidString)?;
            }
            let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
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
        Value::String(s) => {
            strict_parse::validate_string_contents(s, "string value")
                .map_err(JcsError::InvalidString)?;
        }
        Value::Number(n) => {
            number::validate_number(n)?;
        }
        Value::Null | Value::Bool(_) => {}
    }
    Ok(())
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
        Value::Number(number) => number::emit_number(out, number)?,
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

fn emit_string(out: &mut Vec<u8>, value: &str, context: &str) -> Result<(), JcsError> {
    strict_parse::validate_string_contents(value, context).map_err(JcsError::InvalidString)?;

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

fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}
