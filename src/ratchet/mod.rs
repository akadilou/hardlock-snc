pub mod state;
pub mod schedule;

use crate::crypto::aeadx::{seal_xchacha, open_xchacha, rand_nonce, XNONCE_LEN};
use crate::ratchet::state::{RatchetState, Header};
use crate::wire::header_to_bytes;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RatchetError { #[error("decryption failed")] Decrypt, #[error("state desync")] Desync }

/// Initialise le ratchet côté initiateur.
#[must_use]
pub fn init_initiator(root_key: [u8;32], dh_s_priv: [u8;32], dh_r_pub: [u8;32]) -> RatchetState {
    RatchetState::init_initiator(root_key, dh_s_priv, dh_r_pub)
}
/// Initialise le ratchet côté récepteur.
#[must_use]
pub fn init_responder(root_key: [u8;32], dh_s_priv: [u8;32], dh_r_pub: [u8;32]) -> RatchetState {
    RatchetState::init_responder(root_key, dh_s_priv, dh_r_pub)
}

fn make_aad(user_ad: &[u8], header: &Header) -> Vec<u8> {
    let hb = header_to_bytes(header);
    let mut aad = Vec::with_capacity(user_ad.len() + hb.len());
    aad.extend_from_slice(user_ad);
    aad.extend_from_slice(&hb);
    aad
}

/// Chiffre un message (AEAD AAD = ad||header).
#[must_use]
pub fn encrypt(state: &mut RatchetState, ad: &[u8], plaintext: &[u8]) -> (Header, [u8; XNONCE_LEN], Vec<u8>) {
    let (mk, header) = state.next_sending_key();
    let nonce = rand_nonce();
    let aad = make_aad(ad, &header);
    let ct = seal_xchacha(&mk, &nonce, plaintext, &aad);
    (header, nonce, ct)
}

/// Déchiffre un message; rejette les replays.
///
/// # Errors
/// Renvoie `Decrypt` si l’authentification AEAD échoue ou si un replay est détecté.
pub fn decrypt(state: &mut RatchetState, ad: &[u8], header: &Header, nonce: &[u8; XNONCE_LEN], ct: &[u8]) -> Result<Vec<u8>, RatchetError> {
    if state.was_delivered(header) { return Err(RatchetError::Decrypt); }
    let aad = make_aad(ad, header);
    if let Some(mk) = state.try_skipped(header) {
        if let Some(pt) = open_xchacha(&mk, nonce, ct, &aad) { state.mark_delivered(header); return Ok(pt); }
    }
    state.maybe_step(header);
    if header.dh_pub == state.dh_r_pub && header.n > state.nr { state.skip_recv_until(header.n); }
    let mk = state.next_recv_key();
    let out = open_xchacha(&mk, nonce, ct, &aad).ok_or(RatchetError::Decrypt)?;
    state.mark_delivered(header);
    Ok(out)
}
