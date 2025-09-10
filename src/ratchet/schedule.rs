use hkdf::Hkdf;
use sha2::Sha256;

/// KDF Root -> (RK', `CK_s`)
///
/// # Panics
/// Panique si HKDF échoue (théoriquement impossible avec longueurs valides).
#[must_use]
pub fn kdf_rk(root_key: &[u8;32], dh_out: &[u8;32]) -> ([u8;32], [u8;32]) {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_out);
    let mut okm = [0u8;64];
    hk.expand(b"hardlock/ratchet/kdf_rk", &mut okm).expect("hkdf");
    let mut rk = [0u8;32];
    let mut ck = [0u8;32];
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    (rk, ck)
}

/// KDF Chain -> (CK', MK)
///
/// # Panics
/// Panique si HKDF échoue (longueurs invalides).
#[must_use]
pub fn kdf_ck(chain_key: &[u8;32]) -> ([u8;32], [u8;32]) {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut okm = [0u8;64];
    hk.expand(b"hardlock/ratchet/kdf_ck", &mut okm).expect("hkdf");
    let mut ck = [0u8;32];
    let mut mk = [0u8;32];
    ck.copy_from_slice(&okm[..32]);
    mk.copy_from_slice(&okm[32..]);
    (ck, mk)
}
