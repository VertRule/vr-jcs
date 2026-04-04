# vr-jcs

[RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) JSON Canonicalization Scheme (JCS) for deterministic serialization.

[![crates.io](https://img.shields.io/crates/v/vr-jcs.svg)](https://crates.io/crates/vr-jcs)
[![docs.rs](https://docs.rs/vr-jcs/badge.svg)](https://docs.rs/vr-jcs)
[![License: Apache-2.0](https://img.shields.io/crates/l/vr-jcs.svg)](LICENSE)

`vr-jcs` produces RFC 8785 canonical JSON suitable for deterministic digest computation, content hashing, and stable serialization boundaries. Originally developed for the [VertRule](https://github.com/VertRule) receipt infrastructure, it is suitable for any context requiring reproducible JSON output.

## What it does

- Sorts object property names by UTF-16 code units
- Renders numbers using ECMAScript-compatible formatting (via [`zmij`](https://crates.io/crates/zmij))
- Emits canonical JSON with no insignificant whitespace
- Validates I-JSON string constraints (noncharacter rejection)
- Rejects duplicate property names on raw JSON parse paths

## What it does not do

- It is not a general-purpose JSON transformation toolkit
- It does not invent semantics beyond canonicalization
- Duplicate-key rejection applies to raw JSON parse helpers; typed `Serialize` inputs do not carry duplicate keys

## Usage

```rust
use vr_jcs::to_canon_string_from_str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let canon = to_canon_string_from_str(r#"{"z":1,"a":2}"#)?;
    assert_eq!(canon, r#"{"a":2,"z":1}"#);

    // Duplicates are rejected:
    assert!(to_canon_string_from_str(r#"{"a":1,"a":2}"#).is_err());
    Ok(())
}
```

## API

| Function | Description |
|----------|-------------|
| `to_canon_bytes` | Serialize any `Serialize` type to canonical JSON bytes |
| `to_canon_string` | Serialize any `Serialize` type to a canonical JSON string |
| `to_canon_bytes_from_slice` | Parse raw JSON bytes, reject duplicates, return canonical bytes |
| `to_canon_string_from_str` | Parse raw JSON string, reject duplicates, return canonical string |
| `canonicalize` | Sort object keys in-place by UTF-16 code units |

All functions return `Result<_, JcsError>`.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE) for details.
