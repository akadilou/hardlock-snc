use hardlock_snc::kt::*;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn mk_leaf(u: &str, d: &str, pk: &[u8], ts: u64, prev: [u8;32]) -> Leaf {
    Leaf{ user_id:u.into(), device_id:d.into(), pk:pk.to_vec(), ts_ms:ts, prev_hash:prev }
}

#[test]
fn merkle_inclusion_roundtrip() {
    let mut leaves = Vec::new();
    let mut prev = [0u8;32];
    for i in 0..8 {
        let pk = vec![i as u8; 32];
        let l = mk_leaf("user", &format!("dev{}", i), &pk, 1000+i, prev);
        prev = hash_leaf(&l);
        leaves.push(l);
    }
    let hashes: Vec<[u8;32]> = leaves.iter().map(hash_leaf).collect();
    let root = root_from_hashes(hashes.clone());
    for idx in 0..hashes.len() {
        let proof = inclusion_proof(&hashes, idx);
        assert!(verify_inclusion(&root, &hashes[idx], idx, &proof));
    }
}

#[test]
fn sth_sign_verify() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let root = [7u8;32];
    let sth = sign_sth(&sk, 10, root, 123456789);
    assert!(verify_sth(&vk, &sth));
}
