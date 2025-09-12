#ifndef HARDLOCK_SNC_H
#define HARDLOCK_SNC_H



#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define HL_VERSION 272

/**
 * Taille nonce `XChaCha`.
 */
#define XNONCE_LEN 24

/**
 * Taille clé AEAD.
 */
#define KEY_LEN 32

#define HEADER_LEN ((32 + 4) + 4)

#define TYPE_INIT 1

#define TYPE_INIT_AUTH 2

#define HL1_BASE 1

#define HL1_AUTH 2

#define HL1_HYB 17

typedef struct RatchetState RatchetState;

typedef struct RatchetHandle {
  struct RatchetState *ptr;
} RatchetHandle;

/**
 * # Safety
 * Le chargeur d’ABI C doit fournir un pointeur de fonction valide.
 * Aucune précondition supplémentaire.
 */
size_t hardlock_consts_header_len(void);

/**
 * # Safety
 * Le chargeur d’ABI C doit fournir un pointeur de fonction valide.
 * Aucune précondition supplémentaire.
 */
size_t hardlock_consts_nonce_len(void);

/**
 * # Safety
 * `sk_out` et `pk_out` doivent pointer vers des buffers d’au moins 32 octets valides et mutables.
 */
int hardlock_x25519_keygen(uint8_t *sk_out, uint8_t *pk_out);

/**
 * # Safety
 * `pk_recipient32` doit pointer vers 32 octets lisibles.
 * `enc_out` vers un buffer de capacité `enc_cap`.
 * `okm_out32` vers 32 octets mutables.
 */
int hardlock_hpke_initiate(const uint8_t *pk_recipient32,
                           uint8_t *enc_out,
                           size_t enc_cap,
                           uint8_t *okm_out32);

/**
 * # Safety
 * `sk_recipient32` doit pointer vers 32 octets lisibles.
 * `enc_ptr..enc_ptr+enc_len` doit être lisible.
 * `okm_out32` doit pointer vers 32 octets mutables.
 */
int hardlock_hpke_accept(const uint8_t *sk_recipient32,
                         const uint8_t *enc_ptr,
                         size_t enc_len,
                         uint8_t *okm_out32);

/**
 * # Safety
 * Tous les pointeurs doivent référencer 32 octets lisibles (`okm32`, `dh_s_priv32`, `dh_r_pub32`).
 */
struct RatchetHandle *hardlock_ratchet_new_initiator(const uint8_t *okm32,
                                                     const uint8_t *dh_s_priv32,
                                                     const uint8_t *dh_r_pub32);

/**
 * # Safety
 * Tous les pointeurs doivent référencer 32 octets lisibles (`okm32`, `dh_s_priv32`, `dh_r_pub32`).
 */
struct RatchetHandle *hardlock_ratchet_new_responder(const uint8_t *okm32,
                                                     const uint8_t *dh_s_priv32,
                                                     const uint8_t *dh_r_pub32);

/**
 * # Safety
 * `h` doit être un pointeur valide créé par `hardlock_ratchet_new_*` et non libéré auparavant.
 */
void hardlock_ratchet_free(struct RatchetHandle *h);

/**
 * # Safety
 * `h` doit être valide. `ad_ptr/pt_ptr` doivent être lisibles.
 * `header_out/nonce_out/ct_out` doivent être mutables avec suffisamment de capacité (`ct_cap`).
 */
int hardlock_ratchet_encrypt(struct RatchetHandle *h,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *pt_ptr,
                             size_t pt_len,
                             uint8_t *header_out,
                             uint8_t *nonce_out,
                             uint8_t *ct_out,
                             size_t ct_cap);

/**
 * # Safety
 * `h` doit être valide. `header_ptr` doit pointer vers `HEADER_LEN` octets.
 * `nonce_ptr` vers `XNONCE_LEN` octets. `ct_ptr..ct_ptr+ct_len` lisibles.
 * `pt_out` mutable avec `pt_cap` octets.
 */
int hardlock_ratchet_decrypt(struct RatchetHandle *h,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *header_ptr,
                             const uint8_t *nonce_ptr,
                             const uint8_t *ct_ptr,
                             size_t ct_len,
                             uint8_t *pt_out,
                             size_t pt_cap);

/**
 * # Safety
 * `k_s32` doit pointer vers 32 octets lisibles, `sender_pub32` vers 32 octets,
 * `scope_ptr..scope_ptr+scope_len` lisibles, `nonce_out` 24o mutables, `ct_out` capacité `ct_cap`.
 */
int hardlock_token_build(const uint8_t *k_s32,
                         uint64_t expiry_unix_s,
                         const uint8_t *sender_pub32,
                         const uint8_t *scope_ptr,
                         size_t scope_len,
                         uint8_t *nonce_out,
                         uint8_t *ct_out,
                         size_t ct_cap);

/**
 * # Safety
 * `k_s32` 32o lisibles, `nonce_ptr` 24o lisibles, `ct_ptr..ct_ptr+ct_len` lisibles.
 * Retourne 0 si OK, <0 si échec.
 */
int hardlock_token_verify(const uint8_t *k_s32,
                          const uint8_t *nonce_ptr,
                          const uint8_t *ct_ptr,
                          size_t ct_len,
                          uint64_t now_unix_s);

/**
 * # Safety
 * `frame_ptr..frame_ptr+frame_len` lisibles, `out_ptr` capacité `out_cap`.
 * `profile` : 0=Stealth,1=Balanced,2=Throughput. Retourne taille écrite.
 */
int hardlock_apply_padding(const uint8_t *frame_ptr,
                           size_t frame_len,
                           int32_t profile,
                           uint8_t *out_ptr,
                           size_t out_cap);

#endif  /* HARDLOCK_SNC_H */
