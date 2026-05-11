//! Strategy-bearing digest API over RFC 8785 canonical bytes.
//!
//! Canonicalization is a schema decision; digest algorithm choice
//! (BLAKE3 vs. keyed BLAKE3 vs. domain-separated BLAKE3 vs. SHA-256
//! vs. …) is a separate cryptographic / governance decision. This
//! module owns that split.
//!
//! ## Strategy-bearing path
//!
//! For any site whose digest algorithm is or may become a policy
//! variable:
//!
//! - [`DigestAlgorithm`] — the algorithm enum.
//! - [`DigestStrategy`] — an algorithm plus any future policy knobs.
//! - [`CanonicalDigest`] — typed output that remembers which algorithm
//!   produced it.
//! - [`to_canon_digest_with`] — canonicalize `value`, digest under
//!   `strategy`.
//!
//! ## BLAKE3 fixed-policy convenience
//!
//! For sites where receipt policy has explicitly frozen the algorithm
//! to plain BLAKE3:
//!
//! - [`to_canon_blake3_digest`] — `&Value` → `[u8; 32]`.
//! - [`to_canon_blake3_digest_from_slice`] — strict-parse `&[u8]` →
//!   `[u8; 32]`.

use serde_json::Value;

use crate::canonicalize::to_canon_bytes_value;
use crate::error::JcsError;

/// Digest algorithm variant.
///
/// Explicit enum so the algorithm choice is a named governance
/// decision rather than an implicit default.
/// [`Blake3Untagged`](Self::Blake3Untagged) is the plain `blake3::hash`
/// pattern; keyed and domain-separated variants carry their
/// differentiating input so two uses with different keys or contexts
/// cannot accidentally collide on a digest.
///
/// [`Sha256`](Self::Sha256) is declared but not yet wired in this
/// crate; requesting it returns [`JcsError::UnsupportedAlgorithm`].
/// The variant exists so receipt schemas and policy packs can
/// reference it without waiting for the implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// BLAKE3 plain `hash(canonical_bytes)`.
    Blake3Untagged,
    /// BLAKE3 keyed with a 32-byte key: `keyed_hash(key, canonical_bytes)`.
    Blake3Keyed {
        /// Domain key. Value is load-bearing for the digest; choose it
        /// once per receipt domain and never reuse across unrelated
        /// domains.
        key: [u8; 32],
    },
    /// BLAKE3 domain-separated via `derive_key(context, canonical_bytes)`.
    /// The context string is the domain identifier (must be a
    /// compile-time constant in user code — BLAKE3 semantics require
    /// it to be globally unique per domain).
    Blake3DomainSeparated {
        /// Domain context string.
        context: String,
    },
    /// SHA-256 over canonical bytes. Declared in the API but not yet wired.
    Sha256,
}

impl DigestAlgorithm {
    /// Short stable name suitable for use in receipt schemas and logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Blake3Untagged => "blake3-untagged",
            Self::Blake3Keyed { .. } => "blake3-keyed",
            Self::Blake3DomainSeparated { .. } => "blake3-domain-separated",
            Self::Sha256 => "sha256",
        }
    }
}

/// A digest strategy bundles the algorithm with any future policy
/// knobs (output truncation, pre-hash prefix, etc.). Today it's a thin
/// newtype; the wrapper exists so extensions don't churn call sites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestStrategy {
    /// The algorithm to apply.
    pub algorithm: DigestAlgorithm,
}

impl DigestStrategy {
    /// Plain untagged BLAKE3 over canonical bytes.
    #[must_use]
    pub const fn blake3_untagged() -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3Untagged,
        }
    }

    /// Keyed BLAKE3 over canonical bytes.
    #[must_use]
    pub const fn blake3_keyed(key: [u8; 32]) -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3Keyed { key },
        }
    }

    /// Domain-separated BLAKE3 over canonical bytes.
    #[must_use]
    pub fn blake3_domain_separated(context: impl Into<String>) -> Self {
        Self {
            algorithm: DigestAlgorithm::Blake3DomainSeparated {
                context: context.into(),
            },
        }
    }

    /// SHA-256 over canonical bytes. Presently returns
    /// [`JcsError::UnsupportedAlgorithm`] at call time; the
    /// constructor is provided so policy code can reference it today.
    #[must_use]
    pub const fn sha256() -> Self {
        Self {
            algorithm: DigestAlgorithm::Sha256,
        }
    }
}

/// Typed output of a canonical digest computation.
///
/// Carries the algorithm that produced `bytes` so downstream consumers
/// (receipt envelopes, audit logs) can record the algorithm without
/// out-of-band convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalDigest {
    /// The algorithm used.
    pub algorithm: DigestAlgorithm,
    /// Raw digest bytes. Length depends on the algorithm (32 for
    /// BLAKE3 variants, 32 for SHA-256 once wired).
    pub bytes: Vec<u8>,
}

/// Canonicalize a trusted `serde_json::Value` and digest the canonical
/// bytes under the given strategy.
///
/// The value is assumed to come from caller-controlled construction.
/// For untrusted input, use [`crate::to_canon_bytes_from_slice`] first
/// (strict admission) and then pass the resulting `Value` back through
/// this function — or use a strict-parse sibling when one exists for
/// the target strategy.
///
/// # Errors
///
/// Returns:
/// - [`JcsError::Json`] if the value cannot be canonicalized
/// - [`JcsError::InvalidString`] for I-JSON forbidden code points
/// - [`JcsError::InvalidNumber`] for non-interoperable numbers
/// - [`JcsError::NestingDepthExceeded`] for values beyond
///   [`crate::MAX_NESTING_DEPTH`]
/// - [`JcsError::UnsupportedAlgorithm`] if the strategy names an
///   algorithm not wired in this build (e.g. SHA-256 today)
pub fn to_canon_digest_with(
    value: &Value,
    strategy: &DigestStrategy,
) -> Result<CanonicalDigest, JcsError> {
    let bytes = to_canon_bytes_value(value)?;
    let digest_bytes = match &strategy.algorithm {
        DigestAlgorithm::Blake3Untagged => blake3::hash(&bytes).as_bytes().to_vec(),
        DigestAlgorithm::Blake3Keyed { key } => blake3::keyed_hash(key, &bytes).as_bytes().to_vec(),
        DigestAlgorithm::Blake3DomainSeparated { context } => {
            // BLAKE3 derive_key is the standard domain-separated digest:
            // context is the domain identifier, key_material is the data.
            blake3::derive_key(context, &bytes).to_vec()
        }
        DigestAlgorithm::Sha256 => {
            return Err(JcsError::UnsupportedAlgorithm(
                "SHA-256 over canonical bytes is declared in the API but not \
                 wired in this build; open a follow-up to add the sha2 dep"
                    .to_string(),
            ));
        }
    };
    Ok(CanonicalDigest {
        algorithm: strategy.algorithm.clone(),
        bytes: digest_bytes,
    })
}

/// BLAKE3 fixed-policy convenience. Canonicalize `value` and return
/// `blake3::hash(canonical_bytes)` as a 32-byte array.
///
/// Use this only at sites where the receipt convention explicitly
/// fixes the algorithm to plain BLAKE3. For anything else, use
/// [`to_canon_digest_with`] with an explicit [`DigestStrategy`].
///
/// # Errors
///
/// Same as [`to_canon_digest_with`] minus
/// [`JcsError::UnsupportedAlgorithm`].
pub fn to_canon_blake3_digest(value: &Value) -> Result<[u8; 32], JcsError> {
    let bytes = to_canon_bytes_value(value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Strict-parse sibling of [`to_canon_blake3_digest`] for untrusted
/// JSON bytes.
///
/// # Errors
///
/// Returns [`JcsError::Json`] for malformed JSON or duplicate property
/// names, [`JcsError::InvalidString`] or [`JcsError::InvalidNumber`]
/// for I-JSON violations, and [`JcsError::NestingDepthExceeded`] for
/// depth limit breach.
pub fn to_canon_blake3_digest_from_slice(json: &[u8]) -> Result<[u8; 32], JcsError> {
    let bytes = crate::to_canon_bytes_from_slice(json)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
