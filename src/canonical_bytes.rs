//! Newtype boundary over RFC 8785 canonical output bytes.
//!
//! [`CanonicalBytes`] makes "these bytes came out of JCS" a type-level
//! fact that digest, signature, and receipt APIs can statically require.
//! Construction is crate-private — the only way to obtain one is to
//! route through [`crate::canonical_bytes_from_slice`] (or the
//! re-export in `vertrule-core::determinism`).

use std::fmt;

/// Newtype wrapper over canonical JCS output bytes.
///
/// Construction is restricted to this crate — callers obtain a
/// [`CanonicalBytes`] only by routing through
/// [`crate::canonical_bytes_from_slice`] (or the wrappers in
/// `vertrule-core::determinism`). The type exists so digest, signature,
/// and receipt APIs can statically require "bytes that came out of JCS"
/// rather than accepting any `&[u8]`. Every coercion back to `&[u8]`
/// goes through the explicit [`Self::as_slice`] method — there is no
/// `AsRef<[u8]>` or `Deref` impl, so escapes are greppable.
///
/// The `Debug` impl deliberately shows the byte length and not the
/// bytes. Dumping raw canonical JSON into a log is a common way to
/// accidentally leak receipt contents; callers that want the bytes
/// must ask for them.
///
/// # External construction is rejected at compile time
///
/// `from_jcs` is `pub(crate)`. ADR-001 Ratification Criterion #10 binds
/// this privacy as a `compile_fail` doctest:
///
/// ```compile_fail
/// // This must fail to compile — `from_jcs` is pub(crate) and unreachable
/// // from external code. External code MUST route through the strict
/// // path via `canonical_bytes_from_slice`.
/// let _ = vr_jcs::CanonicalBytes::from_jcs(vec![1, 2, 3]);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// Construct from already-canonicalized bytes. Crate-private: the
    /// only way to get a [`CanonicalBytes`] is to feed input through
    /// [`crate::canonical_bytes_from_slice`] (or the re-export in
    /// `vertrule-core::determinism::to_canon_bytes_wrapped`).
    pub(crate) const fn from_jcs(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Explicit escape hatch to a byte slice. Named so reviewers can
    /// grep for the boundary where canonical-bytes discipline is
    /// dropped (e.g., feeding wire bytes to `blake3::hash`).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the canonical output is empty (only possible for an
    /// empty input in degenerate paths; not reachable from the primary
    /// API).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper and return the underlying byte buffer. Use
    /// at wire boundaries where ownership is transferred (file write,
    /// network send). Not an implicit coercion.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for CanonicalBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}
