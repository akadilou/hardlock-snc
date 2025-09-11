use super::StateStore;
use crate::crypto::aeadx::{open_xchacha, rand_nonce, seal_xchacha, KEY_LEN};
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

pub struct FileStore {
    dir: PathBuf,
    key: [u8; KEY_LEN],
}
impl FileStore {
    /// Ouvre un coffre scellé.
    ///
    /// # Errors
    /// Erreurs I/O, paramètres Argon2, dérivation ou chiffrement.
    pub fn open(dir: PathBuf, passphrase: &str, profile: ArgonProfile) -> anyhow::Result<Self> {
        fs::create_dir_all(&dir).ok();
        let salt_path = dir.join(".salt");
        let salt = if salt_path.exists() {
            fs::read(&salt_path)?
        } else {
            let s = SaltString::generate(&mut OsRng);
            fs::write(&salt_path, s.as_str().as_bytes())?;
            s.as_str().as_bytes().to_vec()
        };
        let mut key = [0u8; KEY_LEN];
        derive_key_argon2id(passphrase.as_bytes(), &salt, profile, &mut key)?;
        Ok(Self { dir, key })
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.blob"))
    }
}
fn derive_key_argon2id(
    pass: &[u8],
    salt: &[u8],
    profile: ArgonProfile,
    out: &mut [u8; KEY_LEN],
) -> anyhow::Result<()> {
    let (m_cost, t_cost, p_cost) = match profile {
        ArgonProfile::FAST => (64 * 1024, 3, 1),
        ArgonProfile::BALANCED => (256 * 1024, 3, 1),
        ArgonProfile::STRONG => (1024 * 1024, 3, 1),
    };
    let params = Params::new(m_cost, t_cost, p_cost, Some(out.len()))
        .map_err(|e| anyhow::anyhow!("argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(pass, salt, out)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {:?}", e))?;
    Ok(())
}
#[derive(Clone, Copy)]
pub enum ArgonProfile {
    FAST,
    BALANCED,
    STRONG,
}

impl StateStore for FileStore {
    fn save<T: Serialize>(&mut self, name: &str, value: &T) -> anyhow::Result<()> {
        let b = bincode::serialize(value)?;
        let nonce = rand_nonce();
        let ad = name.as_bytes();
        let ct = seal_xchacha(&self.key, &nonce, &b, ad);
        let mut blob = Vec::with_capacity(4 + nonce.len() + ct.len());
        blob.extend_from_slice(
            &u32::try_from(nonce.len())
                .expect("nonce fits u32")
                .to_le_bytes(),
        );
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        fs::write(self.path(name), blob)?;
        Ok(())
    }
    fn load<T: DeserializeOwned>(&mut self, name: &str) -> anyhow::Result<Option<T>> {
        let path = self.path(name);
        if !path.exists() {
            return Ok(None);
        }
        let blob = fs::read(path)?;
        if blob.len() < 4 {
            anyhow::bail!("corrupt blob");
        }
        let nlen = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
        let nonce = &blob[4..4 + nlen];
        let ct = &blob[4 + nlen..];
        let ad = name.as_bytes();
        let pt = open_xchacha(&self.key, nonce.try_into().unwrap(), ct, ad)
            .ok_or_else(|| anyhow::anyhow!("decrypt"))?;
        Ok(Some(bincode::deserialize::<T>(&pt)?))
    }
    fn remove(&mut self, name: &str) -> anyhow::Result<()> {
        let path = self.path(name);
        if path.exists() {
            fs::remove_file(path).ok();
        }
        Ok(())
    }
}
impl Drop for FileStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
