#include <stdio.h>
#include <string.h>
#include "../include/hardlock_snc.h"

int main() {
    unsigned char skA[32], pkA[32], skB[32], pkB[32];
    if (hardlock_x25519_keygen(skA, pkA) != 0) return 1;
    if (hardlock_x25519_keygen(skB, pkB) != 0) return 1;

    unsigned char enc[1024];
    unsigned char okmA[32], okmB[32];
    int enc_len = hardlock_hpke_initiate(pkB, enc, sizeof enc, okmA);
    if (enc_len <= 0) return 2;
    if (hardlock_hpke_accept(skB, enc, (size_t)enc_len, okmB) != 0) return 3;

    void* ra = hardlock_ratchet_new_initiator(okmA, skA, pkB);
    void* rb = hardlock_ratchet_new_responder(okmB, skB, pkA);
    if (!ra || !rb) return 4;

    const unsigned char ad[] = "ffi-demo";
    const unsigned char msg[] = "hello-ffi";
    unsigned char header[64];
    unsigned char nonce[64];
    unsigned char ct[256];
    int ct_len = hardlock_ratchet_encrypt(ra, ad, sizeof(ad)-1, msg, sizeof(msg)-1, header, nonce, ct, sizeof ct);
    if (ct_len <= 0) return 5;

    unsigned char pt[256];
    int pt_len = hardlock_ratchet_decrypt(rb, ad, sizeof(ad)-1, header, nonce, ct, (size_t)ct_len, pt, sizeof pt);
    if (pt_len <= 0) return 6;

    printf("%.*s\n", pt_len, pt);

    hardlock_ratchet_free(ra);
    hardlock_ratchet_free(rb);
    return 0;
}
