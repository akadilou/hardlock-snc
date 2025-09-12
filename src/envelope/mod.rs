#![allow(clippy::missing_panics_doc)]

use crate::crypto::aeadx::{open_xchacha, rand_nonce, seal_xchacha, KEY_LEN, XNONCE_LEN};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct SenderToken {
    pub nonce: [u8; XNONCE_LEN],
    pub ct: Vec<u8>,
}

#[must_use]
pub fn derive_k_s(master: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut k = [0u8; KEY_LEN];
    hk.expand(b"hardlock/sealed-sender/kS", &mut k)
        .expect("hkdf");
    k
}

#[must_use]
pub fn token_build(
    k_s: &[u8; KEY_LEN],
    expiry_unix_s: u64,
    sender_pub32: &[u8; 32],
    scope: &[u8],
) -> SenderToken {
    let mut pt = Vec::with_capacity(8 + 32 + 2 + scope.len());
    pt.extend_from_slice(&expiry_unix_s.to_le_bytes());
    pt.extend_from_slice(sender_pub32);
    let slen = u16::try_from(scope.len()).expect("scope");
    pt.extend_from_slice(&slen.to_le_bytes());
    pt.extend_from_slice(scope);

    let nonce = rand_nonce();
    let ad = b"hardlock/sealed-sender";
    let ct = seal_xchacha(k_s, &nonce, &pt, ad);
    SenderToken { nonce, ct }
}

#[must_use]
pub fn token_verify(
    k_s: &[u8; KEY_LEN],
    token: &SenderToken,
    now_unix_s: u64,
) -> Option<(u64, [u8; 32], Vec<u8>)> {
    let ad = b"hardlock/sealed-sender";
    let pt = open_xchacha(k_s, &token.nonce, &token.ct, ad)?;
    if pt.len() < 8 + 32 + 2 {
        return None;
    }
    let mut off = 0usize;
    let mut tsb = [0u8; 8];
    tsb.copy_from_slice(&pt[off..off + 8]);
    off += 8;
    let expiry = u64::from_le_bytes(tsb);
    if now_unix_s > expiry {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pt[off..off + 32]);
    off += 32;
    let mut slb = [0u8; 2];
    slb.copy_from_slice(&pt[off..off + 2]);
    off += 2;
    let sl = u16::from_le_bytes(slb) as usize;
    if pt.len() < off + sl {
        return None;
    }
    let scope = pt[off..off + sl].to_vec();
    Some((expiry, pk, scope))
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PadProfile {
    Stealth,
    Balanced,
    Throughput,
}

#[must_use]
pub fn pad_bucket_for(len: usize, profile: PadProfile) -> usize {
    let buckets_stealth = [256, 512, 1024];
    let buckets_bal = [512, 1024, 2048];
    let buckets_tp = [1024, 2048, 4096];
    let buckets = match profile {
        PadProfile::Stealth => &buckets_stealth[..],
        PadProfile::Balanced => &buckets_bal[..],
        PadProfile::Throughput => &buckets_tp[..],
    };
    for &b in buckets {
        if len <= b {
            return b;
        }
    }
    let last = *buckets.last().unwrap();
    len.div_ceil(last).saturating_mul(last)
}

#[must_use]
pub fn apply_padding(mut frame: Vec<u8>, profile: PadProfile) -> Vec<u8> {
    let target = pad_bucket_for(frame.len(), profile);
    if target > frame.len() {
        frame.resize(target, 0);
    }
    frame
}

pub mod transport;
