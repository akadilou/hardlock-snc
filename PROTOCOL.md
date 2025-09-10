# Hardlock SNC — PROTOCOL v1.1

## 0. Suites
HL1 = HPKE{DHKEM(X25519), KDF=HKDF-SHA256, AEAD=ChaCha20-Poly1305}, Ratchet{X25519, HKDF-SHA256, XChaCha20-Poly1305}
HL1-H (option) = HL1 + KEM PQC Kyber-768 (hybride à l'init)

## 1. Handshake HPKE (1→1)
Client (A) → Serveur (aveugle) → B : FRAME_HANDSHAKE_INIT
- type: 0x01
- fields: enc_len:u32 | enc:bytes  (enc = EncappedKey HPKE)
B calcule okm = export("hardlock/export"). A calcule le même okm côté initiateur.
okm (32o) devient la clé racine initiale du Double Ratchet.

## 2. Double Ratchet
State (simplifié) : rk, ck_s, ck_r, dh_s_priv/pk, dh_r_pub, ns, nr, pn, skipped{}
KDF:
- kdf_rk(rk, DH) → rk', ck
- kdf_ck(ck) → ck', mk
Envoi: mk = kdf_ck(ck_s), header = {dh_pub, pn, n}, AEAD_XChaCha20-Poly1305
Réception:
- try_skipped(header) → mk?
- maybe_step(header) (nouvelle DH)
- skip_recv_until(header.n)
- mk = kdf_ck(ck_r), AEAD open

## 3. Trame message (data plane)
frame := ver:u16 | header(40o) | nonce:24o | ct_len:u32 | ct | pad_len:u32 | pad[0..pad_len]
header := dh_pub:32o | pn:u32 | n:u32
AEAD AAD := concat(user_ad, header_bytes)

## 4. Anti-métadonnées de base
- pad_len choisi pour atteindre multiple de pad_to côté client (profil).
- sealed-sender transport (hors SNC) recommandé.

## 5. Erreurs (extraits)
- BAD_VERSION, SHORT_HEADER, TRUNCATED_CT, BAD_AEAD, DESYNC, KEY_CHANGE_PENDING
- Toute altération d’header invalide l’AEAD (header ∈ AAD).

## 6. Stockage local
Argon2id(pass, salt) → key32 ; blob := nonce_len:u32 | nonce:24o | ct
Profils: FAST 64MiB, BALANCED 256MiB, STRONG 1GiB.

## 7. Sécurité et migrations
- PFS/PCS via ratchet.
- Négociation HL1-H signée au niveau contrôle (hors SNC).
- Key Transparency (Merkle+gossip) côté annuaire (hors SNC).


## 1bis. Handshake v2 (négociation + anti-downgrade)

### INIT v2 (Base)
frame := 0x01 | suite:u8 | enc_len:u32 | enc | binder:32
binder := export_K("hardlock/suite-binder" || suite, 32)

### INIT_AUTH v2 (optionnel)
frame := 0x02 | suite:u8 | enc_len:u32 | enc | tag:32 | binder:32
tag    := export_K("hardlock/auth", 32)
binder := export_K("hardlock/suite-binder" || suite, 32)

Réception:
1) Rejeter si suite inconnue.
2) Vérifier binder (mismatch => échec).
3) (INIT_AUTH) calculer tag et comparer (mismatch => échec).
4) Dériver okm et passer au Ratchet.

Suites:
- 0x01 = HL1_BASE (HPKE Base)
- 0x02 = HL1_AUTH (réservé)
- 0x11 = HL1_HYB  (réservé)
