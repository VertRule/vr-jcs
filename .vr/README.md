# .vr/ — Repository State Root

Canonical repo-local state directory for the `vr-jcs` repository.

Governed by Repo State Standard v1.

## Canonical Layout

```
.vr/
  README.md
  governance/
    bindings/
    manifest.toml
    known-nondeterminism.toml
  receipts/
    chain-manifest.json
  state/
  public/
  tmp/
```

## Invariants

1. Exactly one canonical state root: `.vr/`
2. Governance definitions and receipts are strictly separated.
3. No mutable operational files at `.vr/` root level.
4. All path resolution uses `.vr/` prefix, never bare `governance/`.

## Governance Status

| Property | Value |
|----------|-------|
| Governance tier | Utility library (no tier assignment) |
| Determinism stage | 0 — structural |
| Receipt chain | Genesis — no governance receipts produced |
| Authority set | Development — keys derived from plaintext hashing, not managed custody |

### Governance Binding Model

vr-jcs does not bind to formal governance policies. Determinism and safety
are enforced structurally through Cargo.toml lint configuration:

- `float_arithmetic = "deny"` — no floating-point arithmetic
- `panic = "deny"` — no panic paths
- `unwrap_used = "deny"` / `expect_used = "deny"` — no unwrap/expect
- `unsafe_code = "deny"` — no unsafe code
- `print_stdout = "deny"` / `print_stderr = "deny"` — no I/O side effects

This is appropriate for a utility library whose correctness is enforced at
compile time rather than through governance receipts.

### Binding Resolution

The authority-set binding references external governance infrastructure by
BLAKE3 digest rather than by file path. The digest is the BLAKE3 hash of
the canonical authority-set definition (YAML). It is an **anchor**, not a
self-contained proof: to verify it against source material, you need access
to the governance infrastructure. Without it, the digest serves as a
tamper-evident seal.

### What can be verified from a fresh clone

- Code builds and all tests pass: `cargo test`
- RFC 8785 conformance vectors pass: `cargo test --test conformance`
- Lint configuration is machine-readable in Cargo.toml
- No nondeterminism sources in code (verified by clippy + lint config)

### What cannot be verified from a fresh clone

- No governance receipts exist to verify
- Authority set binding references an external governance infrastructure
  (the digest is committed but the source material is not bundled)
- No signature-backed governance evidence has been produced for this repository
