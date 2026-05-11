//! ECMAScript-compatible JSON number rendering per RFC 8785 §3.2.6.
//!
//! Single internal user: [`crate::canonicalize`]. The module keeps the
//! integer-exactness check against IEEE 754 binary64 and the
//! shortest-decimal renderer co-located so RFC 8785 §3.2.6 is auditable
//! in one place.
//!
//! [`emit_number`] writes canonical bytes; [`validate_number`] performs
//! the same admission checks without writing, so [`crate::canonicalize`]
//! can admit a `Value` against the same invariants enforced at emit.

use serde_json::Number;

use crate::error::JcsError;

/// Emit `number` to `out` using ECMAScript shortest-representation rules.
pub(crate) fn emit_number(out: &mut Vec<u8>, number: &Number) -> Result<(), JcsError> {
    if let Some(value) = number.as_i64() {
        let s = value.to_string();
        ensure_exact_binary64_integer(value.unsigned_abs(), &s)?;
        out.extend_from_slice(s.as_bytes());
        return Ok(());
    }

    if let Some(value) = number.as_u64() {
        let s = value.to_string();
        ensure_exact_binary64_integer(value, &s)?;
        out.extend_from_slice(s.as_bytes());
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

/// Validate `number` against the same invariants enforced by
/// [`emit_number`] without writing bytes.
///
/// Used by [`crate::canonicalize::canonicalize`] so an in-place
/// canonicalization rejects values that would later fail at the strict
/// emit pipeline.
pub(crate) fn validate_number(number: &Number) -> Result<(), JcsError> {
    if let Some(value) = number.as_i64() {
        let s = value.to_string();
        return ensure_exact_binary64_integer(value.unsigned_abs(), &s);
    }
    if let Some(value) = number.as_u64() {
        let s = value.to_string();
        return ensure_exact_binary64_integer(value, &s);
    }
    if let Some(value) = number.as_f64() {
        if !value.is_finite() {
            return Err(JcsError::InvalidNumber(
                "encountered a non-finite floating-point number".to_string(),
            ));
        }
        return Ok(());
    }
    Err(JcsError::InvalidNumber(
        "unsupported JSON number representation".to_string(),
    ))
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
