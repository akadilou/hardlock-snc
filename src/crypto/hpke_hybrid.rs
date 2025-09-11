#![allow(clippy::missing_errors_doc)]

use crate::HL_INFO;
use hkdf::Hkdf;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, OpModeR, OpModeS, Serializable,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const EXPORT_LABEL: &[u8] = b"hardlock/export";
const AUTH_LABEL: &[u8] = b"hardlock/auth";
const BINDER_LABEL: &[u8] = b"hardlock/suite-binder";

pub fn hpke_initiate(pk_recipient_bytes: &[u8; 32]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let pk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let (enc, sender_ctx) = setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk_recipient,
        HL_INFO.as_bytes(),
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    sender_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok((enc.to_bytes().to_vec(), okm))
}

pub fn hpke_initiate_deterministic(
    pk_recipient_bytes: &[u8; 32],
    seed32: [u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let pk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut rng = ChaCha20Rng::from_seed(seed32);
    let (enc, sender_ctx) = setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk_recipient,
        HL_INFO.as_bytes(),
        &mut rng,
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    sender_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok((enc.to_bytes().to_vec(), okm))
}

pub fn hpke_accept(sk_recipient_bytes: &[u8; 32], enc_bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let sk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let receiver_ctx = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk_recipient,
        &enc,
        HL_INFO.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    receiver_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(okm)
}

pub fn hpke_initiate_auth(
    sk_sender_bytes: &[u8; 32],
    pk_recipient_bytes: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let sk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let dalek_sk = x25519_dalek::StaticSecret::from(*sk_sender_bytes);
    let pk_sender_bytes = x25519_dalek::PublicKey::from(&dalek_sk).to_bytes();
    let pk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(&pk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let pk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let (enc, sender_ctx) = setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Auth((sk_sender, pk_sender)),
        &pk_recipient,
        HL_INFO.as_bytes(),
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    sender_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok((enc.to_bytes().to_vec(), okm))
}

pub fn hpke_accept_auth(
    pk_sender_bytes: &[u8; 32],
    sk_recipient_bytes: &[u8; 32],
    enc_bytes: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let pk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let sk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let receiver_ctx = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Auth(pk_sender),
        &sk_recipient,
        &enc,
        HL_INFO.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    receiver_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(okm)
}

pub fn hpke_initiate_auth_tagged(
    sk_sender_bytes: &[u8; 32],
    pk_recipient_bytes: &[u8; 32],
) -> anyhow::Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let sk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let dalek_sk = x25519_dalek::StaticSecret::from(*sk_sender_bytes);
    let pk_sender_bytes = x25519_dalek::PublicKey::from(&dalek_sk).to_bytes();
    let pk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(&pk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let pk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let (enc, sender_ctx) = setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Auth((sk_sender, pk_sender)),
        &pk_recipient,
        HL_INFO.as_bytes(),
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    sender_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut tag = [0u8; 32];
    sender_ctx
        .export(AUTH_LABEL, &mut tag)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok((enc.to_bytes().to_vec(), okm, tag))
}

pub fn hpke_accept_auth_check(
    pk_sender_bytes: &[u8; 32],
    sk_recipient_bytes: &[u8; 32],
    enc_bytes: &[u8],
    expected_tag: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let pk_sender = <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_sender_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let sk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let receiver_ctx = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Auth(pk_sender),
        &sk_recipient,
        &enc,
        HL_INFO.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    receiver_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut tag = [0u8; 32];
    receiver_ctx
        .export(AUTH_LABEL, &mut tag)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    if !bool::from(tag.ct_eq(expected_tag)) {
        anyhow::bail!("hpke auth tag mismatch");
    }
    Ok(okm)
}

pub fn hpke_initiate_with_binder(
    pk_recipient_bytes: &[u8; 32],
    suite: u8,
) -> anyhow::Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let pk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PublicKey::from_bytes(pk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let (enc, sender_ctx) = setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base,
        &pk_recipient,
        HL_INFO.as_bytes(),
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    sender_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut binder = [0u8; 32];
    sender_ctx
        .export(&[BINDER_LABEL, &[suite]].concat(), &mut binder)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok((enc.to_bytes().to_vec(), okm, binder))
}

pub fn hpke_accept_with_binder(
    suite: u8,
    sk_recipient_bytes: &[u8; 32],
    enc_bytes: &[u8],
    expected_binder: &[u8; 32],
) -> anyhow::Result<[u8; 32]> {
    let sk_recipient =
        <X25519HkdfSha256 as hpke::kem::Kem>::PrivateKey::from_bytes(sk_recipient_bytes)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let enc = <X25519HkdfSha256 as hpke::kem::Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let receiver_ctx = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk_recipient,
        &enc,
        HL_INFO.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut okm = [0u8; 32];
    receiver_ctx
        .export(EXPORT_LABEL, &mut okm)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let mut binder = [0u8; 32];
    receiver_ctx
        .export(&[BINDER_LABEL, &[suite]].concat(), &mut binder)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    if !bool::from(binder.ct_eq(expected_binder)) {
        anyhow::bail!("binder-mismatch");
    }
    Ok(okm)
}

pub struct HybridSecret {
    pub secret: [u8; 32],
    pub transcript: Vec<u8>,
}

#[must_use]
pub fn derive_initial_secret(
    sk_sender: &StaticSecret,
    pk_recipient: &X25519Public,
) -> HybridSecret {
    let ecdh = sk_sender.diffie_hellman(pk_recipient);
    let mut material = Vec::new();
    material.extend_from_slice(ecdh.as_bytes());
    let mut t = Vec::new();
    t.extend_from_slice(b"HL1:");
    t.extend_from_slice(pk_recipient.as_bytes());
    let hk = kdf32(&material, &t);
    HybridSecret {
        secret: hk,
        transcript: t,
    }
}

fn kdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}
