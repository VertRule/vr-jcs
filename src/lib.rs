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
//! ## Module layout
//!
//! - [`canonicalize`] — RFC 8785 emit + in-place key sorting (also
//!   re-exports the public [`canonicalize()`](crate::canonicalize) function).
//! - [`strict_parse`] — strict admission parser for untrusted JSON
//!   (duplicate-key rejection, I-JSON validation, depth limit).
//! - `digest` — strategy-bearing canonical-bytes digest API.
//! - `canonical_bytes` — [`CanonicalBytes`] newtype boundary.
//! - `number` — internal ECMAScript number rendering (RFC 8785 §3.2.6).
//! - [`error`](crate) — [`JcsError`] / [`JcsErrorInfo`].
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
//! - [`canonicalize()`](crate::canonicalize) — Sort object keys recursively in a `serde_json::Value`
//!   and validate I-JSON strings + numbers.
//!
//! ### Canonical digest
//!
//! Canonicalization is a schema decision; digest algorithm choice (BLAKE3 vs.
//! keyed BLAKE3 vs. domain-separated BLAKE3 vs. SHA-256 vs. …) is a separate
//! cryptographic / governance decision. The digest surface reflects that split:
//!
//! **Strategy-bearing (primary) path** — for any site whose digest algorithm
//! is or may become a policy variable:
//!
//! - [`DigestAlgorithm`] — the algorithm enum.
//! - [`DigestStrategy`] — an algorithm plus any future policy knobs.
//! - [`CanonicalDigest`] — typed output that remembers which algorithm produced it.
//! - [`to_canon_digest_with`] — canonicalize `value`, digest under `strategy`.
//!
//! **BLAKE3 fixed-policy convenience** — for sites where receipt policy has
//! explicitly frozen the algorithm to plain BLAKE3:
//!
//! - [`to_canon_blake3_digest`] — `&Value`  → `[u8; 32]`.
//! - [`to_canon_blake3_digest_from_slice`] — strict-parse `&[u8]` → `[u8; 32]`.
//!
//! These convenience wrappers are equivalent to calling
//! [`to_canon_digest_with`] with [`DigestStrategy::blake3_untagged`] and
//! extracting `bytes`.
//!
//! The lexical invariant is: canonicalization and digest must travel together
//! through one call. Receipt-bound and constitutional code paths MUST use the
//! strategy-bearing or fixed-BLAKE3 wrappers instead of pairing
//! `to_canon_bytes_*` with `blake3::hash` manually.
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

use serde::Serialize;

/// Maximum permitted nesting depth for JSON structures (128).
pub const MAX_NESTING_DEPTH: usize = 128;

mod canonical_bytes;
pub mod canonicalize;
mod digest;
mod error;
mod number;
pub mod strict_parse;

pub use canonical_bytes::CanonicalBytes;
pub use canonicalize::canonicalize;
pub use digest::{
    to_canon_blake3_digest, to_canon_blake3_digest_from_slice, to_canon_digest_with,
    CanonicalDigest, DigestAlgorithm, DigestStrategy,
};
pub use error::{JcsError, JcsErrorInfo};

// Backward-compatible top-level re-exports of strict_parse helpers.
// `vertrule-schemas` and any other sibling-crate consumer reaches these
// through `vr_jcs::*`; the module path `vr_jcs::strict_parse::*` is the
// preferred location for new code.
#[doc(hidden)]
pub use strict_parse::{
    deserialize_json_value_no_duplicates, is_safe_integer, validate_string_contents,
};

// Crate-private re-export so `lib_tests.rs` (an internal test module
// brought in via `#[path = "lib_tests.rs"] mod tests`) can keep its
// `super::*` import shape after the canonicalize-module split.
#[cfg(test)]
pub(crate) use canonicalize::to_canon_bytes_value;

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
    canonicalize::to_canon_bytes_value(&value)
}

/// Serialize any `Serialize` type to a canonical JSON string.
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
    note = "use to_canon_string_from_str for untrusted input; see PUBLIC_SURFACE.md"
)]
pub fn to_canon_string<T: Serialize>(value: &T) -> Result<String, JcsError> {
    let value = serde_json::to_value(value)?;
    let bytes = canonicalize::to_canon_bytes_value(&value)?;
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
    let value = strict_parse::parse_json_value_no_duplicates(json)?;
    canonicalize::to_canon_bytes_value(&value)
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

/// Parse untrusted JSON, apply strict admission checks, and return the
/// canonical RFC 8785 bytes inside a [`CanonicalBytes`] wrapper.
///
/// Prefer this over [`to_canon_bytes_from_slice`] for any path that will
/// feed the bytes into a digest, signature, or receipt primitive — the
/// wrapper makes "came out of JCS" a type-level fact.
///
/// # Errors
///
/// Returns the same errors as [`to_canon_bytes_from_slice`].
pub fn canonical_bytes_from_slice(json: &[u8]) -> Result<CanonicalBytes, JcsError> {
    to_canon_bytes_from_slice(json).map(CanonicalBytes::from_jcs)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
