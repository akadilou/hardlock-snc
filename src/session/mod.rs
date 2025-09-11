use crate::ratchet::state::RatchetState;
use crate::store::fs::{ArgonProfile, FileStore};
use crate::store::StateStore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub peer_id: String,
    pub state: RatchetState,
}
impl Session {
    #[must_use]
    pub fn new(peer_id: String, state: RatchetState) -> Self {
        Self { peer_id, state }
    }
    /// Sauvegarde sur disque.
    ///
    /// # Errors
    /// Erreur si I/O/chiffrement échoue.
    pub fn save_fs(&self, dir: &str, pass: &str) -> anyhow::Result<()> {
        let mut fs = FileStore::open(PathBuf::from(dir), pass, ArgonProfile::BALANCED)?;
        fs.save(&self.peer_id, self)
    }
    /// Charge depuis disque.
    ///
    /// # Errors
    /// Erreur si non trouvé/déchiffrement échoue.
    pub fn load_fs(dir: &str, pass: &str, peer_id: &str) -> anyhow::Result<Self> {
        let mut fs = FileStore::open(PathBuf::from(dir), pass, ArgonProfile::BALANCED)?;
        if let Some(s) = fs.load::<Session>(peer_id)? {
            Ok(s)
        } else {
            anyhow::bail!("not found")
        }
    }
}
