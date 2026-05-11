# vr-jcs v0.4 Release Notes

RFC 8785 JSON Canonicalization Scheme implementation for the VertRule
ecosystem. v0.4 adds first-class digest and canonical-bytes APIs so
callers no longer have to hand-thread `blake3::hash` over canonical
bytes.

## What changed in v0.4.1

- **`strict_parse` submodule promoted to first-class** — strict
  admission helpers are now addressable under `vr_jcs::strict_parse::*`
  with `parse_json_value_no_duplicates`, `deserialize_json_value_no_duplicates`,
  `validate_string_contents`, `is_safe_integer`, and `MAX_SAFE_INTEGER`.
  Top-level `#[doc(hidden)]` re-exports preserved for back-compat;
  new code SHOULD prefer the submodule path
- **Module split for locality** — `src/lib.rs` decomposed into
  `canonicalize`, `strict_parse`, `digest`, `canonical_bytes`,
  `number`, and `error` modules. Public `vr_jcs::*` surface unchanged;
  internal-only reorganization

## What changed since v0.3

- **Canonical digest API** — `to_canon_digest_with(value, strategy)`
  bundles canonicalization with a named [`DigestAlgorithm`]
  (`Blake3Untagged`, `Blake3Keyed`, `Blake3DomainSeparated`, `Sha256`),
  returning a typed `CanonicalDigest` that records which algorithm
  produced the bytes
- **Fixed-policy BLAKE3 helpers** — `to_canon_blake3_digest(value)` and
  `to_canon_blake3_digest_from_slice(json)` are convenience wrappers
  for the common `blake3::hash(canonical_bytes)` pattern; the strict
  sibling validates untrusted input before digesting
- **`CanonicalBytes` newtype** — `canonical_bytes_from_slice(json)`
  returns a wrapper whose construction is crate-private. Digest,
  signature, and receipt APIs can now statically require "bytes that
  came out of JCS" rather than accepting any `&[u8]`. There is no
  `AsRef<[u8]>` or `Deref` impl; coercion goes through explicit
  `as_slice` / `into_vec` so escapes are greppable. The `Debug` impl
  shows length only — never the bytes — to avoid accidental receipt
  leaks in logs
- **`JcsErrorInfo` stable projection** — `JcsError::into_info()`
  collapses to a `Json | Validation` enum so downstream crates can map
  errors without matching on the `#[non_exhaustive]` `JcsError`.
  Future variants flow into `Validation` via `Display`
- **New `JcsError::UnsupportedAlgorithm(String)` variant** — surfaces
  declared-but-unwired algorithms (today: `Sha256`) so policy code
  can name them without a build-time dependency. Additive under
  `#[non_exhaustive]`

## What ships

Strict / typed canonicalization (unchanged from v0.3):

- `to_canon_bytes_from_slice`, `to_canon_string_from_str` — strict
  parse + canonical emit for untrusted JSON
- `to_canon_bytes`, `to_canon_string` — deprecated typed `Serialize`
  path, retained for migration
- `canonicalize` — in-place UTF-16 code-unit key sorting

New in v0.4:

- `canonical_bytes_from_slice` → `CanonicalBytes`
- `CanonicalBytes` (with `as_slice`, `len`, `is_empty`, `into_vec`,
  length-only `Debug`)
- `DigestAlgorithm` (`#[non_exhaustive]`) + `DigestAlgorithm::name()`
- `DigestStrategy` + `blake3_untagged` / `blake3_keyed` /
  `blake3_domain_separated` / `sha256` constructors
- `CanonicalDigest { algorithm, bytes }`
- `to_canon_digest_with`
- `to_canon_blake3_digest`, `to_canon_blake3_digest_from_slice`
- `JcsErrorInfo`, `JcsError::into_info`, `JcsError::UnsupportedAlgorithm`

## Key decisions

- `DigestAlgorithm` is `#[non_exhaustive]` and constructors live on
  `DigestStrategy`. Callers select algorithms by name rather than
  raw enum construction, so adding future algorithms (e.g. SHA-256
  once wired) does not break match arms downstream.
- `CanonicalBytes::from_jcs` is `pub(crate)`. The only way to obtain
  one externally is `canonical_bytes_from_slice` — the strict parse
  path. This is what makes the type a useful boundary marker.
- BLAKE3 domain separation uses `blake3::derive_key(context, bytes)`,
  matching the BLAKE3 spec for domain-separated digests.
- SHA-256 is declared in the API but returns
  `JcsError::UnsupportedAlgorithm` at call time so receipt schemas
  and policy packs can reference it before the implementation lands.

## Migration

No breaking changes. v0.3 callers continue to compile against v0.4.
The deprecated typed path (`to_canon_bytes<T>`, `to_canon_string<T>`)
remains available with the same warnings.

Recommended adoption pattern for new code:

- Use `canonical_bytes_from_slice` over `to_canon_bytes_from_slice`
  when the bytes will feed a digest, signature, or receipt — the
  newtype keeps "JCS-derived" as a type-level fact.
- Use `to_canon_blake3_digest_from_slice` for the common case of
  `blake3::hash(canonical_bytes)` over untrusted input.
- Use `to_canon_digest_with` + `DigestStrategy` when the algorithm
  choice is governance-bearing (keyed or domain-separated digests).

---

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
