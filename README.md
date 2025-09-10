Hardlock — Système Nerveux Central (SNC)
Statut: pré-version technique (non auditée).
Composants: HPKE X25519/HKDF-SHA256, Double Ratchet, XChaCha20-Poly1305, Argon2id, PQC optionnel Kyber-768.
Build:
cargo build
cargo test
cargo run --example chat -- --rounds 3
PQC:
cargo build --features hybrid-pqc
