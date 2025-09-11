use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Leaf {
    pub user_id: String,
    pub device_id: String,
    #[serde(with = "serde_bytes")]
    pub pk: Vec<u8>,
    pub ts_ms: u64,
    pub prev_hash: [u8; 32],
}

fn le_u32(x: u32) -> [u8; 4] {
    x.to_le_bytes()
}
fn le_u64(x: u64) -> [u8; 8] {
    x.to_le_bytes()
}

fn encode_leaf(l: &Leaf) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&le_u32(
        u32::try_from(l.user_id.len()).expect("len fits u32"),
    ));
    v.extend_from_slice(l.user_id.as_bytes());
    v.extend_from_slice(&le_u32(
        u32::try_from(l.device_id.len()).expect("len fits u32"),
    ));
    v.extend_from_slice(l.device_id.as_bytes());
    v.extend_from_slice(&le_u32(u32::try_from(l.pk.len()).expect("len fits u32")));
    v.extend_from_slice(&l.pk);
    v.extend_from_slice(&le_u64(l.ts_ms));
    v.extend_from_slice(&l.prev_hash);
    v
}

#[must_use]
pub fn hash_leaf(l: &Leaf) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(encode_leaf(l));
    h.finalize().into()
}

fn hash_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

#[must_use]
pub fn root_from_hashes(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        let mut h = Sha256::new();
        h.update(b"HL-KT-EMPTY");
        return h.finalize().into();
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_node(&left, &right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

#[must_use]
pub fn merkle_root(leaves: &[Leaf]) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
    root_from_hashes(hashes)
}

#[must_use]
pub fn inclusion_proof(hashes: &[[u8; 32]], mut idx: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        let sib = if idx % 2 == 0 {
            if idx + 1 < level.len() {
                level[idx + 1]
            } else {
                level[idx]
            }
        } else {
            level[idx - 1]
        };
        proof.push(sib);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(hash_node(&left, &right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    proof
}

#[must_use]
pub fn verify_inclusion(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    idx: usize,
    proof: &[[u8; 32]],
) -> bool {
    let mut acc = *leaf_hash;
    let mut i = idx;
    for s in proof {
        acc = if i % 2 == 0 {
            hash_node(&acc, s)
        } else {
            hash_node(s, &acc)
        };
        i /= 2;
    }
    &acc == root
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sth {
    pub tree_size: u64,
    pub root: [u8; 32],
    pub timestamp_ms: u64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

fn sth_to_bytes(sth: &Sth) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 32 + 8 + 6);
    v.extend_from_slice(b"HL-STH");
    v.extend_from_slice(&le_u64(sth.tree_size));
    v.extend_from_slice(&sth.root);
    v.extend_from_slice(&le_u64(sth.timestamp_ms));
    v
}

#[must_use]
pub fn sign_sth(sk: &SigningKey, tree_size: u64, root: [u8; 32], timestamp_ms: u64) -> Sth {
    let mut s = Sth {
        tree_size,
        root,
        timestamp_ms,
        sig: Vec::new(),
    };
    let m = sth_to_bytes(&s);
    let sig = sk.sign(&m);
    s.sig = sig.to_bytes().to_vec();
    s
}

/// Vérifie la signature du STH. Renvoie `false` si invalide.
#[must_use]
pub fn verify_sth(vk: &VerifyingKey, sth: &Sth) -> bool {
    if sth.sig.len() != 64 {
        return false;
    }
    let m = sth_to_bytes(sth);
    let arr: [u8; 64] = match sth.sig.clone().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig: Signature = Signature::from_bytes(&arr);
    vk.verify(&m, &sig).is_ok()
}
