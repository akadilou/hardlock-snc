# Security Policy

## Scope
This policy covers the Hardlock SNC core (Rust crates, FFI, SDK bindings) and the CI/CD guardrails that protect supply chain, UB, and unsafe usage.

## Threat-model anchors
- Constant-time, misuse-resistant crypto with pinned versions.
- No unreviewed `unsafe` in application code; FFI boundary isolated.
- Reproducible builds and deterministic CI gates on every change to `main`.

## CI/CD Guardrails (enforced)
1. Lint pedantic: `clippy::pedantic` with `-D warnings`.
2. Tests: `cargo test --locked`.
3. Supply chain: `cargo deny check`.
4. Unsafe tracking: `cargo geiger` JSON artifact; no app-level `unsafe`.
5. UB detection: Miri on nightly (`miri.yml`) across the workspace.
6. Coverage: Cobertura XML artifact (tarpaulin on Ubuntu).
7. Fuzzing: `cargo-fuzz` with ASan on glibc target; artifacts uploaded.
8. Main protection: direct pushes to `main` blocked; PR merges only.

## Reporting a vulnerability
Preferred: email security@hardlock.local with PoC and impact. Triage within 72h, coordinated disclosure by default.

## Key handling and transparency
- Key Transparency: signed STH (Ed25519), inclusion proofs verified in CI tests.
- FFI ABI stability: `cdylib` + generated C header tracked as artifact.

## Supported releases
`main` is the only supported branch. CI badges in README must be green for a release to be considered valid.
