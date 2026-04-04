# vr-jcs v0.3 Release Notes

RFC 8785 JSON Canonicalization Scheme implementation for the VertRule
ecosystem. Single authoritative source for all receipt canonicalization.

## What changed since v0.2

- **Strict path promoted to primary API** — `to_canon_bytes_from_slice`
  and `to_canon_string_from_str` are now the recommended entry points
  for all trust-bearing code paths
- **Typed path deprecated** — `to_canon_bytes<T>` and `to_canon_string<T>`
  remain available but emit deprecation warnings; migrate to the strict
  path for untrusted input
- **Nesting depth limits** — all paths enforce `MAX_NESTING_DEPTH = 128`,
  preventing stack exhaustion on adversarial input
- **Pretty-printed input accepted** — strict path now accepts any valid
  JSON formatting (including whitespace) and canonicalizes it

## What ships

- `to_canon_bytes_from_slice`, `to_canon_string_from_str` — strict
  parse + canonical emit for untrusted JSON
- `to_canon_bytes`, `to_canon_string` — deprecated typed `Serialize`
  path for caller-controlled construction
- `canonicalize` — in-place UTF-16 code-unit key sorting
- `JcsError` error type with `NestingDepthExceeded` variant
- ECMAScript-compatible number rendering via `zmij`
- I-JSON string validation (noncharacter rejection)
- Duplicate property name rejection on strict parse paths

## Key decisions

- `serde_json` uses `preserve_order` + `arbitrary_precision` features.
  `preserve_order` makes `canonicalize()` behave correctly: insertion
  order is retained after sorting.
- Duplicate-key detection uses `BTreeSet` (not `HashSet`) for
  deterministic iteration — no nondeterminism in error paths.
- RFC 8785 conformance vectors added as committed test fixtures.
- Three helpers (`deserialize_json_value_no_duplicates`,
  `validate_string_contents`, `is_safe_integer`) are `pub` but marked
  `#[doc(hidden)]`. They exist for sibling-crate access and are not
  part of the stable v0.3 contract. See `PUBLIC_SURFACE.md`.

## Consumers

- `vertrule-schemas` depends on `vr-jcs` for internal canonicalization
- `vertrule-verifier` depends on `vr-jcs` directly (not via schemas)
- All JCS consumers in the ecosystem use this crate directly
