use hardlock_snc::crypto::hpke_hybrid::{hpke_accept_auth_check, hpke_initiate_auth_tagged};
use hardlock_snc::identity::DeviceIdentity;

#[test]
fn hpke_auth_ok() {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let (enc, okm_a, tag) =
        hpke_initiate_auth_tagged(&a.x25519.sk.clone().try_into().unwrap(), &b.x25519.public())
            .unwrap();
    let okm_b = hpke_accept_auth_check(
        &a.x25519.public(),
        &b.x25519.sk.clone().try_into().unwrap(),
        &enc,
        &tag,
    )
    .unwrap();
    assert_eq!(okm_a, okm_b);
}

#[test]
fn hpke_auth_wrong_sender_rejected() {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let c = DeviceIdentity::generate("c".into(), "d3".into());
    let (enc, _okm_a, tag) =
        hpke_initiate_auth_tagged(&a.x25519.sk.clone().try_into().unwrap(), &b.x25519.public())
            .unwrap();
    let bad = hpke_accept_auth_check(
        &c.x25519.public(),
        &b.x25519.sk.clone().try_into().unwrap(),
        &enc,
        &tag,
    );
    assert!(bad.is_err());
}
