# Hardlock SNC — Threat Model (v1.1)

## Actifs protégés
- Contenu des messages, fichiers et métadonnées de contenu (intégrité/confidentialité).
- Clés d’identité et d’appareil, états Ratchet, secrets de stockage local.
- Confidentialité des destinataires (niveau transport hors SNC).

## Adversaires
- Observateur réseau passif/actif (MITM).
- Relais malveillant.
- Attaquant client-remote (spam, replays, injections).
- Compromis de device (malware/spyware).
- État-nation (capacité Q— future).

## Hypothèses
- RNG correct OS/DRBG.
- HPKE (RFC9180) et primitives X25519/Ed25519/XChaCha20-Poly1305 sûres.
- Code applicatif ne logge pas secrets.
- Sans mode “trust on first use”, une vérification clé initiale est attendue hors SNC.

## Propriétés visées
- E2EE, authentification d’expéditeur (si signatures actives), intégrité, PFS/PCS via Double Ratchet.
- Anti-tamper d’entête (header ∈ AAD).
- Anti-replay (cache FIFO livré).
- Rétention locale chiffrée (Argon2id + AEAD).
- Framing paddé.

## Surfaces d’attaque et mitigations
- MITM initial: exigence vérification (SAS/QR) hors SNC.
- Substitution de header: AAD lie header au message (bloqué).
- Replay: cache livré (clé=(dh_pub,n), LRU 4k).
- DoS mémoire: cap skipped keys (2k) + FIFO.
- Métadonnées réseau: padding frame; sealed-sender/transport (hors SNC).
- Compromis device: fenêtres de session courtes/app (hors SNC); coffrage local Argon2id.

## Hors périmètre SNC (à spécifier ailleurs)
- Annuaire/Key Transparency (Merkle + gossip).
- Sealed-sender et transport obfusqué.
- Attestation d’intégrité du device/OS.
- Groupes/MLS, multi-devices, rotation et révocation.
