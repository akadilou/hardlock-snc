use crate::crypto::keys::{Ed25519Identity, X25519KeyPair};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeviceIdentity {
    pub user_id: String,
    pub device_id: String,
    pub ed25519: Ed25519Identity,
    pub x25519: X25519KeyPair,
}
impl DeviceIdentity {
    #[must_use]
    pub fn generate(user_id: String, device_id: String) -> Self {
        Self {
            user_id,
            device_id,
            ed25519: Ed25519Identity::generate(),
            x25519: X25519KeyPair::generate(),
        }
    }
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.ed25519.sign(msg)
    }
    /// Retourne la clé de vérification.
    ///
    /// # Panics
    /// Panique si la clé Ed25519 est invalide (ne doit pas arriver).
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let pk: [u8; 32] = self.ed25519.pk.clone().try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap()
    }
}
