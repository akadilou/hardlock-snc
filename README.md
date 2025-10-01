Hardlock — Système Nerveux Central (SNC)
Statut: pré-version technique (non auditée).
Composants: HPKE X25519/HKDF-SHA256, Double Ratchet, XChaCha20-Poly1305, Argon2id, PQC optionnel Kyber-768.
Build:
cargo build
cargo test
cargo run --example chat -- --rounds 3
PQC:
cargo build --features hybrid-pqc

[![ci](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml)

## Features
- HPKE base + auth (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), binder anti-downgrade
- Double Ratchet (X25519 + HKDF-SHA256 + XChaCha20-Poly1305), out-of-order, anti-replay
- Wire framing compact, padding configurable, KATs et fuzz
- FFI C stable (cdylib) + échantillon C
- CI: build, tests, clippy strict, cargo-deny

## Quick start (Rust)
```bash
cargo build
cargo test
cargo run --example chat
cargo run --example chat_v2


## Features
- HPKE base + auth (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), binder anti-downgrade
- Double Ratchet (X25519 + HKDF-SHA256 + XChaCha20-Poly1305), out-of-order, anti-replay
- Wire framing compact, padding configurable, KATs et fuzz
- FFI C stable (cdylib) + échantillon C
- CI: build, tests, clippy strict, cargo-deny

## Quick start (Rust)
```bash
cargo build
cargo test
cargo run --example chat
cargo run --example chat_v2


## Perf
Voir `README_PERF.md`

## Sécurité
- Pas de `unsafe` dans la lib, sauf module FFI
- AEAD: XChaCha20-Poly1305
- KDF: HKDF-SHA256
- HPKE: X25519/HKDF-SHA256/ChaCha20-Poly1305
- Ratchet out-of-order, anti-replay
- Binder v2 anti-downgrade
- CI cargo-deny ok


## Boucliers CI/CD

### Couverture
Mesure la part du code réellement exercée par les tests (artefact Cobertura attaché aux runs).
Reproduction:
```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --all --workspace --out Xml --timeout 120


- **Unsafe Gate** : bloque si `unsafe` apparaît hors de `src/ffi.rs`.
- **Geiger Report** : export JSON de l’empreinte `unsafe` (artefact non-bloquant).
- **Miri** : exécution interprétée pour traquer UB/violations mémoire.
- **Coverage (tarpaulin)** : couverture de tests (rapport Cobertura en artefact).

```bash
# Unsafe Gate local
if grep -R -n -w 'unsafe' src | grep -v '^src/ffi.rs' ; then echo "UNSAFE leak"; exit 1; fi

cargo install cargo-geiger --locked
cargo geiger --all --locked --output-format Json > geiger.json || true

rustup component add --toolchain nightly miri
cargo +nightly miri setup
cargo +nightly miri test

cargo install cargo-tarpaulin --locked
cargo tarpaulin --all --workspace --out Xml --timeout 120


## Boucliers CI/CD

### 1) Couverture de tests (Tarpaulin)
- Workflow: `coverage.yml` (artefact Cobertura).
- Local:
```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --all --workspace --out Xml --timeout 120


## CI/CD

[![ci](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml)
[![miri](https://github.com/akadilou/hardlock-snc/actions/workflows/miri.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/miri.yml)
[![coverage](https://github.com/akadilou/hardlock-snc/actions/workflows/coverage.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/coverage.yml)
[![geiger-report](https://github.com/akadilou/hardlock-snc/actions/workflows/geiger_report.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/geiger_report.yml)
[![unsafe-gate](https://github.com/akadilou/hardlock-snc/actions/workflows/unsafe_gate.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/unsafe_gate.yml)

## CI/CD Guards (audit overview)

- Lint pedantic: `clippy::pedantic`, `-D warnings`
- Tests (locked): `cargo test --workspace --all-features --locked`
- Supply chain: `cargo deny check`
- Unsafe tracking: `cargo geiger` (artifact JSON)
- Miri: UB checks on nightly (`miri.yml`)
- Coverage: tarpaulin Cobertura artifact
- Fuzz: ASan on `x86_64-unknown-linux-gnu`, artifacts (non-blocking)
- Main guard: no direct push to `main` (PR merges only)

See `SECURITY.md` and `CONTRIBUTING.md` for details.
