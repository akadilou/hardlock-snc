use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// Taille nonce `XChaCha`.
pub const XNONCE_LEN: usize = 24;
/// Taille clé AEAD.
pub const KEY_LEN: usize = 32;

/// Chiffre un message avec XChaCha20-Poly1305.
/// 
/// # Panics
/// Panique si l'AEAD échoue (usage invalide ou environnement corrompu).
#[must_use]
pub fn seal_xchacha(key: &[u8; KEY_LEN], nonce: &[u8; XNONCE_LEN], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad: ad }).expect("encrypt")
}

/// Déchiffre un message XChaCha20-Poly1305. Renvoie `None` si l'authentification échoue.
#[must_use]
pub fn open_xchacha(key: &[u8; KEY_LEN], nonce: &[u8; XNONCE_LEN], ct: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: ad }).ok()
}

/// Génère un nonce aléatoire 24o.
#[must_use]
pub fn rand_nonce() -> [u8; XNONCE_LEN] {
    let mut n = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}
