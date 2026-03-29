# vr-jcs v0.2.0 Release Notes

RFC 8785 JSON Canonicalization Scheme implementation for the VertRule
ecosystem. Single authoritative source for all receipt canonicalization.

## What ships

- `to_canon_bytes`, `to_canon_string` — serialize any `Serialize` type
  to canonical JSON
- `to_canon_bytes_from_slice`, `to_canon_string_from_str` — parse raw
  JSON with duplicate-key rejection, return canonical output
- `canonicalize` — in-place UTF-16 code-unit key sorting (observable
  via `preserve_order`)
- `JcsError` error type
- ECMAScript-compatible number rendering via `zmij`
- I-JSON string validation (noncharacter rejection)

## Key decisions

- `serde_json` uses `preserve_order` + `arbitrary_precision` features.
  `preserve_order` makes `canonicalize()` behave correctly: insertion
  order is retained after sorting.
- Three helpers (`deserialize_json_value_no_duplicates`,
  `validate_string_contents`, `is_safe_integer`) are `pub` but marked
  `#[doc(hidden)]`. They exist for sibling-crate access and are not
  part of the stable v0.1 contract. See `PUBLIC_SURFACE.md`.

## Consumers

- `vertrule-schemas` depends on `vr-jcs` for internal canonicalization
- `vertrule-verifier` depends on `vr-jcs` directly (not via schemas)
- All JCS consumers in the ecosystem use this crate directly
