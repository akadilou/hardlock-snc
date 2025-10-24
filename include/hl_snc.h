#ifndef HL_SNC_H
#define HL_SNC_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
void* hl_snc_session_new_initiator(void);
void hl_snc_session_free(void* h);
int hl_snc_encrypt(void* h,const uint8_t* in,size_t in_len,uint8_t* out,size_t* out_len);
int hl_snc_decrypt(void* h,const uint8_t* in,size_t in_len,uint8_t* out,size_t* out_len);
#ifdef __cplusplus
}
#endif
#endif
