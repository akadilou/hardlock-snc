# 🧠 Hardlock-SNC — *Système Nerveux Cryptographique*

> **Rust-based secure communication core**  
> Combining HPKE, Double Ratchet, AEAD, and Argon2id under a unified, auditable, FFI-ready architecture.  
> Designed for embedded, mobile, and distributed systems that require quantum-resilient cryptography and reproducible CI/CD.

---

[![CI](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/ci.yml)
[![Coverage](https://github.com/akadilou/hardlock-snc/actions/workflows/coverage.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/coverage.yml)
[![Miri](https://github.com/akadilou/hardlock-snc/actions/workflows/miri.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/miri.yml)
[![Unsafe Gate](https://github.com/akadilou/hardlock-snc/actions/workflows/unsafe_gate.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/unsafe_gate.yml)
[![SDK Artifacts](https://github.com/akadilou/hardlock-snc/actions/workflows/sdks.yml/badge.svg)](https://github.com/akadilou/hardlock-snc/actions/workflows/sdks.yml)

---

## 🔍 Présentation

Hardlock-SNC (*Système Nerveux Cryptographique*) est une librairie Rust de sécurité post-binaire, combinant :

- 🔐 **HPKE** *(Hybrid Public Key Encryption)* — X25519 + HKDF-SHA256 + ChaCha20-Poly1305  
- 🔄 **Double Ratchet** — out-of-order / anti-replay / context-based re-sync  
- 🧩 **FFI stable C ABI** — exportable vers C / Dart / Android / iOS  
- 🧱 **CI/CD intégral** — coverage, unsafe-gate, Miri, fuzz, SDK build  
- 🧬 **Binder v2** — protection anti-downgrade au niveau handshake  
- 🧠 **PQC ready** — support expérimental Kyber-768 via `--features hybrid-pqc`

---

## 🚀 Quick Start (Rust)

```bash
cargo build --release
cargo test
cargo run --example chat -- --rounds 3

Avec option PQC (Kyber-768)

cargo build --features hybrid-pqc


⸻

🧩 Architecture

hardlock-snc/
├─ src/
│  ├─ hpke/           # Handshake HPKE base + auth
│  ├─ ratchet/        # Double Ratchet out-of-order
│  ├─ aead/           # AEAD XChaCha20-Poly1305
│  ├─ token.rs        # Token auth / anti-replay
│  ├─ ffi.rs          # C ABI (cdylib)
│  └─ lib.rs
├─ benches/
│  ├─ hpke_bench.rs
│  ├─ aead_bench.rs
│  ├─ argon_bench.rs
│  └─ ratchet_bench.rs
├─ include/hardlock_snc.h
└─ examples/chat_v2.rs


⸻

🧰 Fonctionnalités clés

Catégorie	Détails
HPKE Base	X25519 / HKDF-SHA256 / ChaCha20-Poly1305
Auth / Binder v2	Anti-downgrade + tag binding
Double Ratchet	Out-of-order, anti-replay, AEAD XChaCha20
Wire Framing	Frames binaires compactes + padding adaptatif
Tokens	Encodage portable + expiration + signature
FFI	Exports C stables + tests Dart/Android
CI/CD	Tests, Miri, Fuzz, Unsafe Gate, Coverage
PQC Optionnel	Kyber-768 (hybrid mode)


⸻

🧱 API C (FFI)

En-tête : include/hardlock_snc.h

void* hl_snc_session_new_initiator(void);
void  hl_snc_session_free(void* handle);

int hl_snc_encrypt(void* h, const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t* out_len);
int hl_snc_decrypt(void* h, const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t* out_len);

int hl_snc_session_save(void* h, uint8_t* out, size_t* out_len);
int hl_snc_session_load(const uint8_t* in, size_t len, void** h_out);

int hl_token_build(const void* payload, size_t len,
                   uint8_t* out, size_t* out_len);
int hl_token_verify(const uint8_t* token, size_t len);

📘 Voir README_SDK.md pour la documentation complète SDK (FFI + Android + Dart).

⸻

⚙️ Codes d’erreur

Code	Description
0	OK
-1	Entrée nulle
-2	Taille insuffisante
-3	Session invalide
-4	MAC invalide
-5	Token expiré
-6	Erreur interne


⸻

🧪 Tests & Benchmarks

Lancer tous les tests

cargo test --workspace --all-features --locked

Benchmarks

cargo bench --bench hpke_bench
cargo bench --bench aead_bench
cargo bench --bench argon_bench

📈 Résultats détaillés dans README_PERF.md

⸻

🧬 Sécurité & Auditabilité

Contrôle	Description
Unsafe Gate	Refuse toute section unsafe hors de ffi.rs
Geiger Report	Export JSON des dépendances marquées unsafe
Miri	Détection UB (Undefined Behavior) via interprétation mémoire
Coverage	cargo-tarpaulin — rapport XML Cobertura
Fuzz	Tests aléatoires (libFuzzer + ASan)
Guard-Main	Interdiction de push direct sur main
CI Linux/macOS/Android	Build multi-plateforme & artefacts SDK


⸻

🔐 Sécurité cryptographique
	•	AEAD : XChaCha20-Poly1305
	•	KDF : HKDF-SHA256
	•	HPKE : X25519 / HKDF-SHA256 / ChaCha20-Poly1305
	•	Ratchet : out-of-order + anti-replay
	•	Binder v2 : protection anti-downgrade
	•	PQC : Kyber-768 (option --features hybrid-pqc)
	•	Argon2id pour stockage clé privée
	•	Aucune dépendance unsafe en production

⸻

🧩 CI/CD Workflows

Workflow	Description
ci.yml	Build, tests, lint, deny
miri.yml	UB / Unsafe check
coverage.yml	Génération rapport Cobertura
geiger_report.yml	Détection unsafe dépendances
unsafe_gate.yml	Bloque toute fuite unsafe
sdks.yml	Build multi-plateforme (desktop + Android)
sdk-tests.yml	Validation dynamique FFI


⸻

🧰 Reproduction locale

# Vérification du style
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Sécurité dépendances
cargo deny check

# Bench + coverage
cargo bench --profile release
cargo tarpaulin --out Xml


⸻

📚 Documentation technique

Fichier	Sujet
README_API.md	API complète (HPKE, Ratchet, Tokens, Wire)
README_SDK.md	Intégration SDK (C, Dart, Android)
README_PERF.md	Résultats de performance et benchs
SECURITY.md	Politique de sécurité et audit
CONTRIBUTING.md	Guide de contribution
THREATMODEL.md	Modèle de menace et scénarios d’attaque


⸻

🧠 Philosophie

“Binary computing created speed; post-binary computing brings coherence.”
Hardlock-SNC est la première pierre du système Quintium8 Z78 — une architecture symbolique à 8 états inspirée du vivant.
Le SNC (Système Nerveux Cryptographique) en est le noyau de communication sécurisé, garantissant résilience, intégrité et symétrie d’information.

⸻

📜 Licence

Apache 2.0
© 2025 Q8NeuroTech / Tufkey Labs
Usage libre, attribution requise.

⸻

🧩 Liens
	•	README_API.md
	•	README_SDK.md
	•	README_PERF.md
	•	Q8NeuroTech.org (à venir)

⸻

Conçu et optimisé sous supervision cryptographique Q8NeuroTech.
Build Repro ID : $(git rev-parse --short HEAD)
État CI : stable ✅
