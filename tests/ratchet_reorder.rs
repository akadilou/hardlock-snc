use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::crypto::hpke_hybrid::hpke_initiate;
use hardlock_snc::ratchet;

#[test]
fn out_of_order_decrypt() {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let (enc, s_a) = hpke_initiate(&b.x25519.public()).unwrap();
    let s_b = hardlock_snc::crypto::hpke_hybrid::hpke_accept(&b.x25519.sk.clone().try_into().unwrap(), &enc).unwrap();
    let mut ra = ratchet::init_initiator(s_a, a.x25519.sk.clone().try_into().unwrap(), b.x25519.public());
    let mut rb = ratchet::init_responder(s_b, b.x25519.sk.clone().try_into().unwrap(), a.x25519.public());
    let ad = b"ad";
    let (h1, n1, c1) = ratchet::encrypt(&mut ra, ad, b"m1");
    let (h2, n2, c2) = ratchet::encrypt(&mut ra, ad, b"m2");
    let p2 = ratchet::decrypt(&mut rb, ad, &h2, &n2, &c2).unwrap();
    let p1 = ratchet::decrypt(&mut rb, ad, &h1, &n1, &c1).unwrap();
    assert_eq!(&p2, b"m2");
    assert_eq!(&p1, b"m1");
}
