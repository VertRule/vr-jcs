# vr-jcs — JSON Canonicalization Scheme (RFC 8785)

set shell := ["bash", "-euo", "pipefail", "-c"]

# Default: show help
default:
    @just --list

# Format check + clippy + rustdoc
lint:
    cargo fmt -- --check
    cargo clippy --all-targets -- -D warnings

# Run all tests
test:
    cargo test

# Full CI check
ci: lint test
    @echo "All checks passed."

# Tier-3 contract name matched by the governance pre-push resolver.
verify: ci
