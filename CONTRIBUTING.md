# Contributing

## Workflow
1. Branch from `main`. Direct pushes to `main` are forbidden; use PRs.
2. Local gate: run `scripts/ci-local.sh` (fmt, clippy pedantic, tests, deny, geiger; optional miri/coverage/fuzz).
3. Open a PR with clear description and motivation; link issues if applicable.
4. CI must be fully green: `ci` (lint, test, deny, geiger, coverage, gate) and `miri`.

## Commit rules
- Conventional, imperative subject (≤72 chars). Scope when useful.
- No commented-out code; no TODOs without an issue link.

## Code quality gates (summary)
- `clippy::pedantic` + `-D warnings`
- tests `--locked`
- `cargo-deny`
- `cargo-geiger` JSON artifact
- Miri nightly
- tarpaulin Cobertura artifact
- fuzz ASan on glibc target (non-blocking by default)

## Unsafe and FFI
Application Rust must not use `unsafe`. FFI modules are the only allowed boundary and are audited.
