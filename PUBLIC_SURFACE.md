# vr-jcs Public Surface (v0.3)

Canonical RFC 8785 JSON Canonicalization Scheme implementation
for the `VertRule` ecosystem.

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

## Constants

```rust
/// Maximum permitted nesting depth (128).
pub const MAX_NESTING_DEPTH: usize = 128;
```

## Error Type

```rust
pub enum JcsError {
    Json(serde_json::Error),
    InvalidString(String),
    InvalidNumber(String),
    NestingDepthExceeded,
}
```

## Not Part of the Stable v0.3 Contract

The following symbols are `pub` for sibling-crate access but are
marked `#[doc(hidden)]` and excluded from semver protection:

- `#[doc(hidden)] deserialize_json_value_no_duplicates`
- `#[doc(hidden)] validate_string_contents`
- `#[doc(hidden)] is_safe_integer`

These may change or be removed without a semver bump. They ship
as `#[doc(hidden)]` in v0.3.0 because `vertrule-schemas` still
depends on `deserialize_json_value_no_duplicates`. A future release
may gate them behind `feature = "unstable"` or inline them into
consuming crates.
