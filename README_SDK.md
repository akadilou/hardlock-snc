# Hardlock SNC – SDK Intégrateur

## Contenu
- Linux: libhardlock_snc.so + hardlock_snc.h
- Android: libhardlock_snc.so (arm64-v8a) + hardlock_snc.h
- iOS (si activé): HardlockSNC.xcframework + hardlock_snc.h
- CI: zip unifié sdk-bundle-<run_id>.zip (workflow `ffi`) et release zip sur tag (workflow `release`)

## API C (extrait)
- hl_snc_session_new_initiator() -> void*
- hl_snc_session_free(void*)
- hl_snc_encrypt(void*, const uint8_t*, size_t, uint8_t*, size_t*)
- hl_snc_decrypt(void*, const uint8_t*, size_t, uint8_t*, size_t*)
- hl_snc_session_save(void*, uint8_t*, size_t*)
- hl_snc_session_load(const uint8_t*, size_t, void**)
- hl_token_build(...), hl_token_verify(...), hl_apply_padding(...)

Les tailles exactes (HEADER_LEN, NONCE_LEN, etc.) et la liste complète sont dans le header généré `hardlock_snc.h`.

## Codes d’erreur
- 0 = OK
- <0 = erreur (tampon insuffisant, entrée invalide, session nulle, etc.)

## Examples ---
### C (Linux)
```c
#include "hardlock_snc.h"
#include <stdint.h>
#include <stdio.h>
int main(void){
  uint8_t out_ct[4096]; size_t ct_len=sizeof(out_ct);
  uint8_t out_pt[4096]; size_t pt_len=sizeof(out_pt);
  void* s = hl_snc_session_new_initiator();
  const uint8_t msg[]="hello";
  if(hl_snc_encrypt(s,msg,sizeof(msg)-1,out_ct,&ct_len)!=0) return 2;
  if(hl_snc_decrypt(s,out_ct,ct_len,out_pt,&pt_len)!=0) return 3;
  fwrite(out_pt,1,pt_len,stdout);
  hl_snc_session_free(s);
  return 0;
}
