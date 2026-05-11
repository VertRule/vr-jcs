# vr-jcs Public Surface (v0.4)

Canonical RFC 8785 JSON Canonicalization Scheme implementation
for the `VertRule` ecosystem. v0.4 adds the canonical digest API
and the `CanonicalBytes` newtype boundary; the v0.3 strict / typed
distinction below carries forward unchanged.

## API Path Distinction

vr-jcs exposes two canonicalization paths with different trust properties.

### Strict path (for untrusted external JSON)

These functions parse untrusted JSON, apply strict admission checks
(duplicate-key rejection, I-JSON validation, nesting depth limits),
and emit canonical RFC 8785 bytes. **Use these when the input is
untrusted.**

```rust
pub fn to_canon_bytes_from_slice(json: &[u8]) -> Result<Vec<u8>, JcsError>;
pub fn to_canon_string_from_str(json: &str) -> Result<String, JcsError>;
```

### Typed path (for caller-controlled construction only)

These functions accept any `Serialize` type and canonicalize the
serialized output. The typed `Serialize` path is **not authoritative
for untrusted raw JSON** because it does not control parse-time
object-member admission — duplicate keys, noncharacter strings, and
other raw-JSON violations are invisible to this path. Use only when
the caller fully controls construction of `T`.

**Deprecated since v0.3.0.** Prefer the strict path for all new
trust-bearing code paths. These functions remain available during
the migration period.

```rust
#[deprecated]
pub fn to_canon_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError>;
#[deprecated]
pub fn to_canon_string<T: Serialize>(value: &T) -> Result<String, JcsError>;
```

### In-place canonicalization

Sorts object keys recursively by UTF-16 code units. For digest
computation, prefer `to_canon_bytes_from_slice` which handles
the full strict parse + canonical emit pipeline.

```rust
pub fn canonicalize(v: &mut serde_json::Value) -> Result<(), JcsError>;
```

## Strict-Bytes Newtype (v0.4)

`CanonicalBytes` is a wrapper over canonical JCS output bytes whose
construction is crate-private. Digest, signature, and receipt APIs
can statically require "bytes that came out of JCS" rather than
accepting any `&[u8]`. There is no `AsRef<[u8]>` or `Deref` impl;
every coercion to `&[u8]` goes through `as_slice` (or `into_vec` at
ownership-transfer boundaries) so escapes are greppable. The `Debug`
impl shows the byte length only — never the bytes themselves —
preventing accidental receipt leaks in logs.

```rust
pub fn canonical_bytes_from_slice(json: &[u8]) -> Result<CanonicalBytes, JcsError>;

pub struct CanonicalBytes(/* private */);

impl CanonicalBytes {
    pub fn as_slice(&self) -> &[u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn into_vec(self) -> Vec<u8>;
}
```

Prefer `canonical_bytes_from_slice` over `to_canon_bytes_from_slice`
on any path that will feed the bytes into a digest, signature, or
receipt primitive.

## Canonical Digest API (v0.4)

`to_canon_digest_with` bundles canonicalization with a named digest
algorithm and returns a typed `CanonicalDigest` that records the
algorithm alongside the bytes. Use this when the algorithm choice is
governance-bearing (keyed or domain-separated digests). For the
common fixed-policy `blake3::hash(canonical_bytes)` pattern, the
two BLAKE3 helpers ship an opinionated 32-byte output.

```rust
pub fn to_canon_digest_with(
    value: &serde_json::Value,
    strategy: &DigestStrategy,
) -> Result<CanonicalDigest, JcsError>;

pub fn to_canon_blake3_digest(
    value: &serde_json::Value,
) -> Result<[u8; 32], JcsError>;

pub fn to_canon_blake3_digest_from_slice(
    json: &[u8],
) -> Result<[u8; 32], JcsError>;
```

### `DigestAlgorithm` and `DigestStrategy`

`DigestAlgorithm` is `#[non_exhaustive]` so future algorithms are
additive. Callers construct algorithms through `DigestStrategy`
constructors — never by raw enum construction — so adding variants
does not break match arms downstream. BLAKE3 domain separation uses
`blake3::derive_key(context, bytes)`. SHA-256 is declared in the API
but currently returns `JcsError::UnsupportedAlgorithm` at call time;
the variant exists so receipt schemas and policy packs can reference
it before the implementation lands.

```rust
#[non_exhaustive]
pub enum DigestAlgorithm {
    Blake3Untagged,
    Blake3Keyed { key: [u8; 32] },
    Blake3DomainSeparated { context: String },
    Sha256,
}

impl DigestAlgorithm {
    pub const fn name(&self) -> &'static str;
}

pub struct DigestStrategy {
    pub algorithm: DigestAlgorithm,
}

impl DigestStrategy {
    pub const fn blake3_untagged() -> Self;
    pub const fn blake3_keyed(key: [u8; 32]) -> Self;
    pub fn blake3_domain_separated(context: impl Into<String>) -> Self;
    pub const fn sha256() -> Self;
}

pub struct CanonicalDigest {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}
```

## Constants

```rust
/// Maximum permitted nesting depth (128).
pub const MAX_NESTING_DEPTH: usize = 128;
```

## Error Type

```rust
#[non_exhaustive]
pub enum JcsError {
    Json(serde_json::Error),
    InvalidString(String),
    InvalidNumber(String),
    NestingDepthExceeded,
    /// New in v0.4 — a digest algorithm variant was requested but is not
    /// wired in this build. Today: `Sha256` strategies fail with this.
    UnsupportedAlgorithm(String),
}
```

`JcsError` is `#[non_exhaustive]`. Downstream crates should not match on
its variants directly — use the stable projection below.

### Stable projection for downstream mapping

```rust
pub enum JcsErrorInfo {
    Json(serde_json::Error),
    Validation(String),
}

impl JcsError {
    pub fn into_info(self) -> JcsErrorInfo;
}
```

`JcsErrorInfo` is intentionally exhaustive. Future `JcsError` variants
collapse into `Validation` via `Display`, so adding variants to `JcsError`
will not break downstream matches on `JcsErrorInfo`.

## `strict_parse` Submodule (v0.4.1)

The strict admission helpers are first-class under `vr_jcs::strict_parse`:

```rust
pub mod strict_parse {
    pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    pub fn parse_json_value_no_duplicates(json: &[u8]) -> Result<Value, JcsError>;
    pub fn deserialize_json_value_no_duplicates<'de, D>(de: D) -> Result<Value, D::Error>
        where D: Deserializer<'de>;
    pub fn validate_string_contents(value: &str, context: &str) -> Result<(), String>;
    pub const fn is_safe_integer(value: i64) -> bool;
}
```

Module-level documentation explains the depth-via-sentinel encoding
and the `'$'`-prefix bypass for `serde_json` `arbitrary_precision`
internal sentinels in one place.

For backward compatibility, the top-level re-exports of
`deserialize_json_value_no_duplicates`, `validate_string_contents`,
and `is_safe_integer` remain available under `vr_jcs::*` (marked
`#[doc(hidden)]` to nudge new code to the submodule path).
`parse_json_value_no_duplicates` is reachable only via
`vr_jcs::strict_parse::*` — it had no top-level re-export prior.

## Module layout (v0.4.1)

```
src/canonicalize.rs      RFC 8785 emit + in-place key sort
src/strict_parse.rs      strict admission parser
src/digest.rs            DigestStrategy + CanonicalDigest API
src/canonical_bytes.rs   CanonicalBytes newtype
src/number.rs            ECMAScript shortest-decimal renderer
src/error.rs             JcsError + JcsErrorInfo
src/lib.rs               public-API surface, MAX_NESTING_DEPTH
```

The split is internal locality only — no public symbol moved off the
`vr_jcs::*` root, so all 318 in-tree consumers continue to compile
unchanged. New code SHOULD prefer `vr_jcs::strict_parse::*` when
reaching for I-JSON validation primitives.

## `JcsErrorInfo` is a load-bearing boundary

The two-variant `JcsErrorInfo` projection is **not** decoration over a
flatter `JcsError`. Future architecture passes MUST NOT propose
collapsing them: `JcsError` is `#[non_exhaustive]` precisely because
`JcsErrorInfo` is exhaustive. Future variants of `JcsError` flow into
`JcsErrorInfo::Validation` via `Display`, so adding variants does not
break downstream `match` statements on `JcsErrorInfo`. The projection
is the gate against `JcsError` evolution breaking sibling crates.
