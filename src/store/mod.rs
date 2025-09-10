pub mod mem;
pub mod fs;

use serde::{Serialize, de::DeserializeOwned};

pub trait StateStore {
    /// Sauvegarde sérialisée.
    ///
    /// # Errors
    /// Erreur en cas d’I/O, sérialisation ou chiffrement.
    fn save<T: Serialize>(&mut self, name: &str, value: &T) -> anyhow::Result<()>;
    /// Charge sérialisée.
    ///
    /// # Errors
    /// Erreur si lecture/déchiffrement/parse échoue.
    fn load<T: DeserializeOwned>(&mut self, name: &str) -> anyhow::Result<Option<T>>;
    /// Supprime l’entrée.
    ///
    /// # Errors
    /// Erreur en cas d’I/O (suppression).
    fn remove(&mut self, name: &str) -> anyhow::Result<()>;
}
