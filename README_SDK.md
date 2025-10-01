# Hardlock SNC – SDK Intégrateur

## Contenu
- Artefacts générés par la CI: 
  - Linux: `libhardlock_snc.so` + `hardlock_snc.h`
  - Android: `libhardlock_snc.so` arm64-v8a + `hardlock_snc.h`
  - iOS (si activé): `HardlockSNC.xcframework` + `hardlock_snc.h`
- Paquet consolidé: `sdk-bundle-<run_id>.zip` (Actions → workflow `ffi`) et `sdk_hardlock_snc_vX.Y.Z.zip` (Release GitHub sur tag)

## API C (extrait)
- Création/Destruction: `hl_snc_session_new_initiator() -> void*`, `hl_snc_session_free(void*)`
- Chiffrement/Déchiffrement: 
  - `int hl_snc_encrypt(void* s, const uint8_t* pt, size_t pt_len, uint8_t* out_ct, size_t* out_ct_len)`
  - `int hl_snc_decrypt(void* s, const uint8_t* ct, size_t ct_len, uint8_t* out_pt, size_t* out_pt_len)`
- Persistance: `int hl_snc_session_save(void* s, uint8_t* out, size_t* out_len)`, `int hl_snc_session_load(const uint8_t* in, size_t in_len, void** out_s)`
- Sealed-sender: `int hl_token_build(...); int hl_token_verify(...);`
- Padding: `int hl_apply_padding(uint8_t profile, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len)`

Les tailles exactes (ex: `HEADER_LEN`, `NONCE_LEN`) et la liste complète des fonctions sont dans `hardlock_snc.h` (généré).

### Codes d’erreur
- 0 = OK
- < 0 = erreur (tampon insuffisant, entrée invalide, session nulle, etc.)

### Exemple C minimal
Voir workflow `sdk-tests.yml`, job `linux_c_echo_test`.

## iOS (Swift)
```swift
import HardlockSNC
let s = HardlockSession.initiator()
let c = try s.encrypt(Data("hello".utf8))
let p = try s.decrypt(c)

## Android (Kotlin/JNI)
```kotlin
object HL {
    init { System.loadLibrary("hardlock_snc") }
    external fun sessionNewInitiator(): Long
    external fun encrypt(h: Long, input: ByteArray): ByteArray
    external fun decrypt(h: Long, input: ByteArray): ByteArray
    external fun sessionFree(h: Long)
}

## Examples --- C (Linux)
```c
#include "hardlock_snc.h"
#include <stdint.h>
#include <stdio.h>
int main(){ uint8_t ct[4096]; size_t cl=sizeof(ct); uint8_t pt[4096]; size_t pl=sizeof(pt); void* s=hl_snc_session_new_initiator(); const uint8_t msg[]="hello"; hl_snc_encrypt(s,msg,sizeof(msg)-1,ct,&cl); hl_snc_decrypt(s,ct,cl,pt,&pl); fwrite(pt,1,pl,stdout); hl_snc_session_free(s); }
```

## Examples --- Swift (iOS)
```swift
import HardlockSNC
let s = HardlockSession.initiator()
let c = try s.encrypt(Data("hello".utf8))
let p = try s.decrypt(c)
```

## Examples --- Kotlin (Android)
```kotlin
object HL {
    init { System.loadLibrary("hardlock_snc") }
    external fun sessionNewInitiator(): Long
    external fun encrypt(h: Long, input: ByteArray): ByteArray
    external fun decrypt(h: Long, input: ByteArray): ByteArray
    external fun sessionFree(h: Long)
}
```

