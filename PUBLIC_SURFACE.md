# vr-jcs Public Surface (v0.2)

Canonical RFC 8785 JSON Canonicalization Scheme implementation
for the VertRule ecosystem.

## Stable Public API

```rust
// Serialize any Serialize type to canonical JSON
pub fn to_canon_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, JcsError>;
pub fn to_canon_string<T: Serialize>(value: &T) -> Result<String, JcsError>;

// Parse raw JSON and return canonical output (rejects duplicate keys)
pub fn to_canon_bytes_from_slice(json: &[u8]) -> Result<Vec<u8>, JcsError>;
pub fn to_canon_string_from_str(json: &str) -> Result<String, JcsError>;

// Sort object keys in-place by UTF-16 code units (observable with preserve_order)
pub fn canonicalize(v: &mut serde_json::Value);

// Error type
pub enum JcsError {
    Json(serde_json::Error),
    InvalidString(String),
    InvalidNumber(String),
}
```

## Not Part of the Stable v0.2 Contract

The following symbols are `pub` for sibling-crate access but are
marked `#[doc(hidden)]` and excluded from semver protection:

- `deserialize_json_value_no_duplicates`
- `validate_string_contents`
- `is_safe_integer`

These may change or be removed without a semver bump. If they are
still needed at publish time, they will be gated behind
`feature = "unstable"`.
