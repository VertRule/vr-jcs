//! Strict admission parser for untrusted JSON input.
//!
//! All public functions in this module enforce the same RFC 8785 / I-JSON
//! invariants used by the strict canonical-emit pipeline:
//!
//! - **Duplicate property names** are rejected at parse time. Object
//!   members are tracked in a [`BTreeSet`] (deterministic) so the
//!   rejection error path itself is order-stable.
//! - **Forbidden Unicode noncharacters** in strings and property names
//!   reject. Specifically: the range `U+FDD0..=U+FDEF`, plus any code
//!   point with the bottom 16 bits matching `U+xFFFE` or `U+xFFFF`.
//! - **Nesting depth** is capped at [`crate::MAX_NESTING_DEPTH`]. The
//!   limit is enforced via a sentinel-encoded serde error that
//!   [`parse_json_value_no_duplicates`] unwraps back into
//!   [`JcsError::NestingDepthExceeded`].
//!
//! Sibling crate `vertrule-schemas` consumes [`deserialize_json_value_no_duplicates`],
//! [`validate_string_contents`], and [`is_safe_integer`] for its own
//! schema-validation pipeline.
//!
//! # The `'$'`-prefix exception
//!
//! `serde_json` with `arbitrary_precision` enabled uses internal
//! sentinel keys like `"$serde_json::private::Number"` during number
//! deserialization. Those sentinels would otherwise look like ordinary
//! property names to this visitor. We bypass [`validate_string_contents`]
//! for any key starting with `'$'` so the sentinel survives. This
//! intentionally over-matches — a user key like `"$ref"` containing a
//! noncharacter would not be validated. Acceptable because forbidden
//! noncharacters in `'$'`-prefixed keys are vanishingly unlikely in
//! practice.

use std::collections::BTreeSet;

use serde::de::{self, DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::{Number, Value};

use crate::error::JcsError;
use crate::MAX_NESTING_DEPTH;

/// I-JSON safe integer ceiling (`2^53 - 1`).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Sentinel prefix used by [`NoDuplicateValueSeed`] to signal depth
/// exceeded through serde's error channel. Matched in
/// [`parse_json_value_no_duplicates`] to promote the error to
/// [`JcsError::NestingDepthExceeded`].
const DEPTH_EXCEEDED_SENTINEL: &str = "nesting depth exceeded maximum of ";

/// Parse untrusted JSON bytes, rejecting duplicate property names,
/// I-JSON-forbidden code points, and JSON numbers that cannot be admitted
/// under the JCS number contract, while enforcing [`MAX_NESTING_DEPTH`].
///
/// Number admission uses [`crate::number::validate_number`] so this
/// entry point enforces the same admission predicate as the canonical
/// emit pipeline. ADR-001 binds this uniformity across all strict-path
/// entry points.
///
/// # Errors
///
/// - [`JcsError::Json`] for malformed JSON or duplicate property names.
/// - [`JcsError::InvalidString`] for forbidden noncharacters.
/// - [`JcsError::InvalidNumber`] for non-finite or non-exactly-representable numbers.
/// - [`JcsError::NestingDepthExceeded`] for depth limit breach.
pub fn parse_json_value_no_duplicates(json: &[u8]) -> Result<Value, JcsError> {
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
    validate_all_numbers(&value)?;
    Ok(value)
}

/// Recursively validate every `Number` in `value` against the JCS
/// admission predicate defined in [`crate::number::validate_number`].
fn validate_all_numbers(value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Number(n) => crate::number::validate_number(n),
        Value::Array(arr) => arr.iter().try_for_each(validate_all_numbers),
        Value::Object(map) => map.values().try_for_each(validate_all_numbers),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// Deserialize a JSON value while rejecting duplicate property names.
///
/// Used by `vertrule-schemas` for ingestion validation.
///
/// # Errors
///
/// Returns an error if the input contains duplicate property names,
/// forbidden noncharacters, or is otherwise invalid JSON.
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
pub fn validate_string_contents(value: &str, context: &str) -> Result<(), String> {
    if let Some(ch) = value.chars().find(|&ch| is_noncharacter(ch)) {
        return Err(format!(
            "{context} contains the forbidden noncharacter U+{:04X}",
            ch as u32
        ));
    }
    Ok(())
}

/// Check if an integer is in the I-JSON safe integer range
/// `[-2^53+1, 2^53-1]`.
#[must_use]
pub const fn is_safe_integer(value: i64) -> bool {
    value >= -MAX_SAFE_INTEGER && value <= MAX_SAFE_INTEGER
}

const fn is_noncharacter(ch: char) -> bool {
    let code = ch as u32;
    (0xFDD0 <= code && code <= 0xFDEF) || code & 0xFFFE == 0xFFFE
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

        // See module-level docs: '$'-prefix bypass for serde_json
        // arbitrary_precision sentinels.
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
            // Same '$'-prefix bypass as above; see module-level docs.
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
