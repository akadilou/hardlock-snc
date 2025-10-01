# Mon SDK

# Explication
- `README_SDK.md` donne le **mode d’emploi intégrateur** et renvoie au header C généré (source de vérité des prototypes et constantes ABI). Ça évite toute divergence si tu renomme des symboles.
- `ffi.yml` publie trois artefacts:
  - Linux C: `.so` + `hardlock_snc.h`
  - iOS: `HardlockSNC.xcframework` créé avec `xcodebuild -create-xcframework` à partir de `libhardlock_snc.a` pour device + simulator
  - Android: `.so` arm64-v8a via `cargo-ndk`, plus le header
- Aucun commentaire mélangé dans les blocs exécutables, tout est copiable.

# Prochain pas
1) Va sur la PR ouverte par la commande, vérifie que le workflow **ffi** passe.
2) Télécharge les artefacts depuis l’onglet du workflow pour valider localement:
   - Compiler le petit C sample avec le header (Linux/macOS).
   - Lier l’`XCFramework` dans un projet Xcode vide.
   - Charger la `.so` Android dans un projet test avec `jniLibs`.
3) Si une étape échoue (ex: nom de crate différent de `hardlock-snc`, ou nom de lib), envoie-moi le log précis → je te renvoie un **patch ciblé** (nom de crate, chemin, cible, etc.).

