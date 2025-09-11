use hardlock_snc::crypto::hpke_hybrid::hpke_initiate;
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;

#[test]
fn reject_replay_same_header() {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let (enc, s_a) = hpke_initiate(&b.x25519.public()).unwrap();
    let s_b = hardlock_snc::crypto::hpke_hybrid::hpke_accept(
        &b.x25519.sk.clone().try_into().unwrap(),
        &enc,
    )
    .unwrap();

    let mut ra = ratchet::init_initiator(
        s_a,
        a.x25519.sk.clone().try_into().unwrap(),
        b.x25519.public(),
    );
    let mut rb = ratchet::init_responder(
        s_b,
        b.x25519.sk.clone().try_into().unwrap(),
        a.x25519.public(),
    );
    let ad = b"ad";

    let (h, n, ct) = ratchet::encrypt(&mut ra, ad, b"m");
    let pt1 = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).unwrap();
    assert_eq!(&pt1, b"m");
    let pt2 = ratchet::decrypt(&mut rb, ad, &h, &n, &ct);
    assert!(pt2.is_err());
}
