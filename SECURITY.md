# Security

## Scope
- Library cryptographique sans `unsafe` (hors module FFI).
- AEAD: XChaCha20-Poly1305
- KDF: HKDF-SHA256
- HPKE: X25519/HKDF-SHA256/ChaCha20-Poly1305, binder v2 anti-downgrade.
- Double Ratchet: X25519 + HKDF-SHA256, out-of-order, anti-replay persistant.

## Dépendances
- `cargo deny` en CI pour vulnérabilités, licences, sources.

## Tests
- Unitaires
- Tests de propriété
- Simulation e2e réordonnée
- Fuzz wire

## Signalement
- Ouvrir une issue privée sur GitHub si nécessaire.
- Aucun secret de prod ne doit être communiqué dans les tickets.

## Limites
- Pas d’effacement mémoire garanti au-delà de ce que fournissent les crates.
- Pas encore d’audit externe complet.

