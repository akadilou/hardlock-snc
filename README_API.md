# Hardlock-SNC — API Technique

> Basé sur HPKE (Hybrid Public Key Encryption) + Double Ratchet + AEAD XChaCha20-Poly1305  
> Fournit une interface C stable pour la sérialisation, le chiffrement, et la réinitialisation sécurisée des sessions.

---

## 🧩 Modules Principaux

| Module | Description | Fonctions clés |
|:--|:--|:--|
| **HPKE** | Handshake (base, auth, binder) entre deux pairs. | `hpke_initiate`, `hpke_accept`, `hpke_initiate_auth_tagged`, `hpke_accept_auth_check`, `hpke_initiate_with_binder`, `hpke_accept_with_binder` |
| **Ratchet** | Double ratchet asynchrone avec anti-rejeu et messages hors ordre. | `init_initiator`, `init_responder`, `encrypt`, `decrypt` |
| **Wire Framing** | Encodage/decodage compact (frame binaire, padding). | `encode_init_v2`, `decode_init_v2` |
| **Token / Session** | Sérialisation, restauration, et expiration des tokens de session. | `hl_token_build`, `hl_token_verify`, `hl_snc_session_save`, `hl_snc_session_load` |

---

## 🔐 Handshake HPKE

### Base
```rust
let (enc, okm) = hpke_initiate(&pkR)?;
let okm2 = hpke_accept(&skR, &enc)?;

	•	pkR: clé publique du récepteur.
	•	okm: Output Keying Material — clé dérivée.
	•	Algorithmes: X25519 + HKDF-SHA256 + ChaCha20-Poly1305.

Authentifié (taggé)

let (enc, okmA, tag) = hpke_initiate_auth_tagged(&skA, &pkR)?;
let okmB = hpke_accept_auth_check(&pkA, &skR, &enc, &tag)?;

	•	Authentifie l’expéditeur via skA/pkA.
	•	Inclut un tag dérivé pour validation croisée.

Handshake v2 (binder anti-downgrade)

let (enc, okmA, binder) = hpke_initiate_with_binder(&pkR, suites::HL1_BASE)?;
let frame = encode_init_v2(suites::HL1_BASE, &enc, &binder);
let (suite, enc2, binder2) = decode_init_v2(&frame)?;
let okmB = hpke_accept_with_binder(suite, &skR, &enc2, &binder2)?;

	•	binder empêche un downgrade de suite cryptographique.
	•	Encodage compact frame (wire-level).

⸻

🔁 Ratchet (Double Ratchet)

Initialisation symétrique :

let mut ra = init_initiator(okmA, skA, pkR);
let mut rb = init_responder(okmB, skR, pkA);

Chiffrement / déchiffrement :

let ad = b"ctx";
let (h,n,ct) = encrypt(&mut ra, ad, b"hello");
let pt = decrypt(&mut rb, ad, &h, &n, &ct)?;

	•	ad : données associées.
	•	h : en-tête.
	•	n : nonce.
	•	ct : ciphertext.
	•	pt : plaintext (restauré).

Caractéristiques :
	•	Out-of-order decrypt (gestion des messages désynchronisés).
	•	Anti-replay (vérification des nonces utilisés).
	•	Re-synchronisation adaptative via “skip table”.

⸻

🧾 Tokenisation & Sessions

Sérialisation d’une session

int hl_snc_session_save(void* session, uint8_t* out, size_t* out_len);

Restauration

int hl_snc_session_load(const uint8_t* data, size_t len, void** session_out);

Gestion du cycle de vie

void* hl_snc_session_new_initiator(void);
void  hl_snc_session_free(void* handle);

Token (auth)

int hl_token_build(const void* payload, size_t len, uint8_t* out, size_t* out_len);
int hl_token_verify(const uint8_t* token, size_t len);

Exemple :

void* s = hl_snc_session_new_initiator();
uint8_t token[256];
size_t token_len = sizeof(token);
hl_token_build("user42", 6, token, &token_len);
hl_token_verify(token, token_len);
hl_snc_session_free(s);


⸻

⚙️ API C complète (extrait)

Fonction	Signature	Description
hl_snc_session_new_initiator	void* ()	Crée une session initiatrice
hl_snc_session_free	void (void*)	Libère une session
hl_snc_encrypt	int (void*, const uint8_t*, size_t, uint8_t*, size_t*)	Chiffre un buffer
hl_snc_decrypt	int (void*, const uint8_t*, size_t, uint8_t*, size_t*)	Déchiffre un buffer
hl_snc_session_save	int (void*, uint8_t*, size_t*)	Sérialise une session
hl_snc_session_load	int (const uint8_t*, size_t, void**)	Recharge une session
hl_token_build	int (const void*, size_t, uint8_t*, size_t*)	Crée un token signé
hl_token_verify	int (const uint8_t*, size_t)	Vérifie un token
hl_apply_padding	int (uint8_t*, size_t, size_t)	Ajoute un padding configurable

⚠️ Toutes les fonctions renvoient 0 si succès, <0 sinon.
Les tailles sont toujours exprimées en octets (size_t).

⸻

🧠 Codes d’erreur

Code	Signification
0	OK
-1	Entrée nulle
-2	Taille insuffisante
-3	Session invalide
-4	Tampon out-of-bounds
-5	MAC invalide
-6	Token invalide / expiré
-7	Internal error


⸻

🧪 Exemple complet (C)

#include "hardlock_snc.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
  uint8_t out_ct[4096]; size_t ct_len = sizeof(out_ct);
  uint8_t out_pt[4096]; size_t pt_len = sizeof(out_pt);
  void* s = hl_snc_session_new_initiator();
  const uint8_t msg[] = "hello_hardlock";

  if (hl_snc_encrypt(s, msg, sizeof(msg)-1, out_ct, &ct_len) != 0)
    return 2;
  if (hl_snc_decrypt(s, out_ct, ct_len, out_pt, &pt_len) != 0)
    return 3;

  fwrite(out_pt, 1, pt_len, stdout);
  hl_snc_session_free(s);
  return 0;
}

Sortie :

hello_hardlock


⸻

🔬 Benchmarks rapides (Rust)

cargo bench --bench hpke_bench
cargo bench --bench ratchet_bench
cargo bench --bench argon_bench


⸻

🧱 Notes d’implémentation
	•	Implémentation pure Rust, #![forbid(unsafe_code)] sauf dans ffi.rs.
	•	AEAD : XChaCha20-Poly1305
	•	KDF : HKDF-SHA256
	•	HPKE : X25519 / HKDF-SHA256 / ChaCha20-Poly1305
	•	PQC (optionnel) : Kyber768 via feature hybrid-pqc
	•	Anti-downgrade : binder v2
	•	CI : clippy, miri, tarpaulin, geiger, unsafe-gate.

⸻

🔗 Voir aussi
	•	README_SDK.md — pour intégration Android / Flutter.
	•	README_PERF.md — pour les résultats de benchs.
	•	SECURITY.md — pour les aspects de sécurité et audit.

⸻

📜 Licence

Apache 2.0 (par défaut) — usage libre sous réserve d’attribution.
