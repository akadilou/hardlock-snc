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

