# Hardlock SNC — Threat Model (military-grade) — v1.2

**Statut:** Draft / Operational  
**Auteur:** Team Hardlock  
**Date:** 2025-10-23  
**Scope:** Core Rust library (`hardlock_snc`), FFI C ABI, example SDKs (Dart/Android), CI/CD guardrails, deployment infra (Caddy + compose) used to serve API and healthcheck endpoints.

---

## 1 — Objectifs de sécurité (goals)
1. **Confidentialité** : message payloads, keys, ratchet states remain secret.
2. **Intégrité** : messages, headers, and session state cannot be tampered silently.
3. **Authenticité** : parties peuvent vérifier l’origine (signatures / HPKE auth).
4. **Forward/Compromise security** : PFS via HPKE + Ratchet ; post-compromise containment.
5. **Availability** : service résilient face à DoS ciblé mais pas bancal pour load normal.
6. **Supply-chain integrity** : builds reproducibles + CI gates empêchant publication d’artefacts corrompus.
7. **Minimal exposure** : secrets never in repo, CI or logs.

---

## 2 — Actifs (priorisés)
- **A1**: Private long-term identity keys (Ed25519/X25519).
- **A2**: Session/rachet states (OKM, PT, skipped keys).
- **A3**: Message payloads & associated metadata (headers, lengths).
- **A4**: Build artifacts (libhardlock_snc.*) and CI release zips.
- **A5**: Deployment credentials (SSH keys, Docker tokens).
- **A6**: CI secrets and signing keys.
- **A7**: Source code (integrity + provenance).

---

## 3 — Adversaires & capacités
- **ADV1 — Network observer**: passive eavesdrop, can fingerprint sizes/timing.
- **ADV2 — Active MITM**: can intercept/modify in-transit, attempt downgrade.
- **ADV3 — Malicious relay / backend**: can modify server behaviour.
- **ADV4 — Compromised client device**: full local read access.
- **ADV5 — Supply-chain attacker**: compromises CI runner, package repo, or signing keys.
- **ADV6 — Nation-state (future PQ threat)**: has large compute, may demand backdoors.

---

## 4 — Hypothèses opérationnelles
- OS-provided RNG (getrandom) is secure.
- Deploy endpoints (Caddy) run on machines we control by SSH.
- No secret material is stored in plaintext in the repo.
- Admins will approve key transparency / out-of-band verification steps when needed.

---

## 5 — Scénarios d’attaque majeurs & mitigations (military table)

| Scenario | Goal of attacker | Relevant asset | Primary controls | CI / Test |
|---|---:|---|---|---|
| MITM initial handshake | Intercept/alter HPKE handshake to downgrade | A1, A3 | HPKE auth, binder v2 (anti-downgrade), require auth-tag on enrollment | Unit tests for `hpke_initiate_with_binder` roundtrip; CI integration test failing on mismatch |
| Header tampering | Modify header to change recipient / metadata | A3 | Header included in AAD; AEAD sealing of header | Fuzz test: modify header bytes → AEAD open must fail |
| Replay injection | Replay old packet to cause duplicate actions | A2/A3 | Replay cache LRU (4k), nonce check, ratchet counters | Replay acceptance test; coverage asserts replay rejected |
| Local device compromise | Extract keys / ratchet state from device | A1/A2 | Secure local storage + Argon2id for persisted state, short session lifetime | Local zeroize tests, checks that saved session requires Argon2id-derived unlock |
| Supply-chain compromise | Push malicious binary to release | A4/A7 | Signed releases, reproducible builds, cargo-deny, geiger, miri | CI guard: deny on cargo-deny failure, geiger violation blocks release |
| DoS via many sessions | Exhaust memory / ratchet state | Availability | Caps on skipped keys (2k), session limits, rate limiting in edge (Caddy) | Load test + unit for skip-key cap; Caddy rate-limit config enforced in deploy tests |
| PQ-adversary future | Break DH/X25519 | Long-term confidentiality | Hybrid PQ option (Kyber) as opt-in, rotation plan | Hybrid KATs, feature gating tests |

---

## 6 — Defensive controls (detailed)
### Cryptography
- HPKE: X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
- Auth: HPKE auth mode w/ auth tag and binder v2 for anti-downgrade.
- AEAD: XChaCha20-Poly1305 for message sealing.
- KDF: HKDF-SHA256 for ratchet derivations.
- Password stretching: Argon2id for persisted secrets storage.

### Code hygiene
- No `unsafe` except module `src/ffi.rs`. `unsafe` occurrences audited with `cargo geiger`.
- `-D warnings` and `clippy::pedantic` enforced.
- No logging of secrets (linter and pre-commit grep).

### CI gates (must be green to release)
- `cargo test --workspace --locked`
- `cargo deny check`
- `cargo geiger` (artifact)
- `cargo +nightly miri test`
- Coverage (tarpaulin) -> Cobertura artifact
- Fuzz (cargo-fuzz) runs non-blocking with artifacts

### Supply-chain
- Signed releases (gpg/opaque) + ephemeral hash in CI artifacts.
- Reproducible builds: store autosave.json + build environment in artifacts.

### Deployment / Ops
- Reverse proxy (Caddy) enforces TLS, HSTS when ready, security headers (`Referrer-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` optionally).
- Caddy removes `Server` header and other telemetry.
- Rate limiting at edge (e.g. `/api` → 100 req/s burst 200).
- External blackbox monitoring (UptimeRobot / cron job) using DNS bypass when needed.

### Secrets handling
- Never store secrets in repo. Use GitHub Actions secrets + vault.
- Pre-commit hook to detect AWS/GCP/SSH tokens (regex).
- CI job to fail on accidental secret exposure via `git-secrets` scan.

---

## 7 — Tests & checks (mapping)
- Unit tests: handshake, ratchet encrypt/decrypt, header AAD, replay detection.
- Integration tests: HPKE + ratchet end-to-end between two in-memory nodes.
- Fuzz tests: arbitrary input to AEAD/ratchet/decoder.
- Miri test: nightly run to catch UB.
- Geiger: unsafe count report upload as artifact.
- Supply-chain: cargo-deny, dependency pin checks.

**CI rule**: any failure in the above blocks `release` workflow and prevents pushing release tag.

---

## 8 — Incident response playbook (short)
1. **Detect**: CI alert or monitoring alert -> create incident ticket.
2. **Contain**: rotate affected keys (signing/CI), disable CI runners if needed, revoke compromised deploy host SSH key.
3. **Assess**: reproduce exploit, identify scope (which artifacts, which commits).
4. **Recover**: rebuild artifacts from pinned commits on clean runner, sign new release, notify stakeholders.
5. **Communicate**: coordinated disclosure timeline; pre-approved contact `security@<org>`; public advisory if needed.
6. **Post-mortem**: update threat model, tests, and CI gates; block merge until proven fix.

---

## 9 — Operational checklist (military, to run pre-merge / weekly)
- [ ] All unit tests green.
- [ ] `cargo deny` returns zero critical/deny rules.
- [ ] `cargo geiger` shows no new `unsafe` outside `src/ffi.rs`.
- [ ] Miri nightly tests pass on guarded targets.
- [ ] Fuzz run (smoke) did not crash (or crash triaged).
- [ ] Release artefacts reproducible (hash matched).
- [ ] CI secrets rotated every quarter; signing key protected and offline.
- [ ] Deployment host packages up-to-date; unattended-upgrades enabled.
- [ ] External smoke-cron/blackbox checks succeeded 3x in a row (no flakiness).
- [ ] No Server header nor sensitive headers leaked in responses (edge check).
- [ ] Rate limits configured and validated in Caddy config.

---

## 10 — VSCode — workspace & tooling (pratique militaire)
**Recommended Extensions**
- Rust Analyzer (`rust-analyzer`)
- Crates (`serayuzgur.crates`)
- CodeLLDB (for native debugging)
- GitLens
- EditorConfig for consistent formatting
- YAML (redhat.vscode-yaml)
- TODO+ / Better TODO for findings
- Prettier (for markdown)
- `.env` file support

**Workspace settings** (`.vscode/settings.json`)
```json
{
  "files.exclude": { "target": true, "node_modules": true, ".dart_tool": true },
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.checkOnSave.command": "clippy",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll": true
  }
}

Useful VSCode tasks (.vscode/tasks.json)

{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "cargo test",
      "type": "shell",
      "command": "cargo test --workspace --all-features --locked",
      "group": { "kind": "test", "isDefault": true }
    },
    {
      "label": "cargo geiger",
      "type": "shell",
      "command": "cargo geiger --all --locked --output-format Json > geiger.json || true"
    },
    {
      "label": "run miri nightly",
      "type": "shell",
      "command": "cargo +nightly miri test",
      "problemMatcher": []
    }
  ]
}


⸻

11 — Documentation / public exposure guidance
	•	Public repo: keep READMEs neutral, do not reveal signing/CI secrets, IP addresses, or internal endpoints.
	•	Use README_SDK.md to describe public API surface (C header) without publishing developer credentials or sample keys.
	•	For sensitive operational details (hosts, certs, SSH), keep a private ops/ repo (access-controlled).
	•	For releases, prefer signed assets and an attestable provenance artifact (.buildinfo).

⸻

12 — Glossary & references
	•	AAD — Additional Authenticated Data (part of AEAD)
	•	HPKE — Hybrid Public Key Encryption (RFC 9180)
	•	PFS — Perfect Forward Secrecy
	•	PQC — Post-Quantum Cryptography
	•	Geiger — Rust unsafe audit tool
	•	Miri — Rust interpreter for undefined behaviour detection

⸻

13 — Next actions (short)
	1.	Convert this doc to THREATMODEL.md in repo root.
	2.	Add VSCode workspace .vscode/ (settings + tasks) and commit.
	3.	Implement the CI checks mapping (if not present): cargo-deny, cargo-geiger, Miri, fuzz.
	4.	Add scripts/security_selftest.sh to run local smoke tests and replay tests.
	5.	Schedule monthly key rotation and quarterly supply-chain review.

⸻

14 — Notes on secrets (policy)
	•	Never put private keys in repo. Use GitHub Actions secrets or HashiCorp Vault.
	•	Add pre-commit hook to detect private keys and common token patterns.
	•	Rotate any secret that has been accidentally committed (even briefly) — assume compromise.

⸻

Ce document est volontairement précis mais non-exhaustif — il doit évoluer avec le code et les découvertes d’audit.
Pour la version finale, je peux générer aussi :
	•	un THREATMODEL.pdf (diagram + table) ;
	•	scripts/security_selftest.sh prêt à coller ;
	•	./.vscode/* (settings & tasks) commit-ready.
