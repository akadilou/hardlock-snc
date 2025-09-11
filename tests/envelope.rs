use hardlock_snc::envelope::*;
use rand::RngCore;

#[test]
fn token_roundtrip() {
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);
    let k_s = derive_k_s(&master, b"salt");
    let expiry = 4102444800u64;
    let sender_pub = [7u8; 32];
    let scope = b"chat";
    let t = token_build(&k_s, expiry, &sender_pub, scope);
    let out = token_verify(&k_s, &t, 4100000000).expect("verify");
    assert_eq!(out.0, expiry);
    assert_eq!(out.1, sender_pub);
    assert_eq!(out.2, scope);
}

#[test]
fn token_expired() {
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);
    let k_s = derive_k_s(&master, b"salt");
    let t = token_build(&k_s, 1000, &[0u8; 32], b"s");
    assert!(token_verify(&k_s, &t, 2000).is_none());
}

#[test]
fn padding_buckets() {
    let v = vec![1u8; 300];
    let s = apply_padding(v.clone(), PadProfile::Stealth);
    assert_eq!(s.len(), 512);
    let b = apply_padding(v.clone(), PadProfile::Balanced);
    assert_eq!(b.len(), 512);
    let t = apply_padding(v, PadProfile::Throughput);
    assert_eq!(t.len(), 1024);
}
