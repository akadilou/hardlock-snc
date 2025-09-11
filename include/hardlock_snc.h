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

size_t hardlock_consts_header_len(void);

size_t hardlock_consts_nonce_len(void);

int hardlock_x25519_keygen(uint8_t *sk_out, uint8_t *pk_out);

int hardlock_hpke_initiate(const uint8_t *pk_recipient32,
                           uint8_t *enc_out,
                           size_t enc_cap,
                           uint8_t *okm_out32);

int hardlock_hpke_accept(const uint8_t *sk_recipient32,
                         const uint8_t *enc_ptr,
                         size_t enc_len,
                         uint8_t *okm_out32);

struct RatchetHandle *hardlock_ratchet_new_initiator(const uint8_t *okm32,
                                                     const uint8_t *dh_s_priv32,
                                                     const uint8_t *dh_r_pub32);

struct RatchetHandle *hardlock_ratchet_new_responder(const uint8_t *okm32,
                                                     const uint8_t *dh_s_priv32,
                                                     const uint8_t *dh_r_pub32);

void hardlock_ratchet_free(struct RatchetHandle *h);

int hardlock_ratchet_encrypt(struct RatchetHandle *h,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *pt_ptr,
                             size_t pt_len,
                             uint8_t *header_out,
                             uint8_t *nonce_out,
                             uint8_t *ct_out,
                             size_t ct_cap);

int hardlock_ratchet_decrypt(struct RatchetHandle *h,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *header_ptr,
                             const uint8_t *nonce_ptr,
                             const uint8_t *ct_ptr,
                             size_t ct_len,
                             uint8_t *pt_out,
                             size_t pt_cap);

#endif  /* HARDLOCK_SNC_H */
