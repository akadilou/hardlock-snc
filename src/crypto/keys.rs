#![allow(clippy::missing_panics_doc)]

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
use rand_core::{RngCore, CryptoRng};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ed25519Identity {
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sk: Vec<u8>,
}
impl Ed25519Identity {
    #[must_use]
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        Self { pk: pk.to_bytes().to_vec(), sk: sk.to_bytes().to_vec() }
    }
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Signature {
        let sk_bytes: [u8;32] = self.sk.clone().try_into().expect("sk32");
        let sk = SigningKey::from_bytes(&sk_bytes);
        sk.sign(data)
    }
    #[must_use]
    pub fn verify(&self, data: &[u8], sig: &Signature) -> bool {
        let pk_bytes: [u8;32] = self.pk.clone().try_into().expect("pk32");
        let vk = VerifyingKey::from_bytes(&pk_bytes).expect("vk");
        vk.verify(data, sig).is_ok()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct X25519KeyPair {
    #[serde(with = "serde_bytes")]
    pub sk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
}
impl X25519KeyPair {
    #[must_use]
    pub fn generate() -> Self {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = X25519Public::from(&sk);
        Self { sk: sk.to_bytes().to_vec(), pk: pk.to_bytes().to_vec() }
    }
    #[must_use]
    pub fn from_seed(seed32: [u8; 32]) -> Self {
        let sk = StaticSecret::from(seed32);
        let pk = X25519Public::from(&sk);
        Self { sk: sk.to_bytes().to_vec(), pk: pk.to_bytes().to_vec() }
    }
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.pk.clone().try_into().unwrap()
    }
    #[must_use]
    pub fn secret(&self) -> StaticSecret {
        let bytes: [u8;32] = self.sk.clone().try_into().expect("sk32");
        StaticSecret::from(bytes)
    }
}

pub fn csprng_fill(mut rng: impl RngCore + CryptoRng, out: &mut [u8]) {
    rng.fill_bytes(out);
}
