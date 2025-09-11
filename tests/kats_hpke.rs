use hardlock_snc::crypto::hpke_hybrid::{hpke_accept, hpke_initiate_deterministic};
use hardlock_snc::identity::DeviceIdentity;

#[test]
fn hpke_deterministic_kat() {
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let seed = [42u8; 32];
    let (enc, okm_a) = hpke_initiate_deterministic(&b.x25519.public(), seed).expect("init");
    let okm_b = hpke_accept(&b.x25519.sk.clone().try_into().unwrap(), &enc).expect("acc");
    assert_eq!(okm_a, okm_b);
    assert!(!enc.is_empty());
}
