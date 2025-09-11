use hardlock_snc::crypto::hpke_hybrid::{hpke_accept, hpke_initiate};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;

#[test]
fn handshake_and_roundtrip() {
    let alice = DeviceIdentity::generate("alice".into(), "alice-phone".into());
    let bob = DeviceIdentity::generate("bob".into(), "bob-laptop".into());
    let (enc, s_a) = hpke_initiate(&bob.x25519.public()).expect("hpke");
    let s_b = hpke_accept(&bob.x25519.sk.clone().try_into().unwrap(), &enc).expect("hpke");
    let mut r_alice = ratchet::init_initiator(
        s_a,
        alice.x25519.sk.clone().try_into().unwrap(),
        bob.x25519.public(),
    );
    let mut r_bob = ratchet::init_responder(
        s_b,
        bob.x25519.sk.clone().try_into().unwrap(),
        alice.x25519.public(),
    );
    let ad = b"ad";
    let (h, n, ct) = ratchet::encrypt(&mut r_alice, ad, b"msg-1");
    let pt = ratchet::decrypt(&mut r_bob, ad, &h, &n, &ct).expect("decrypt");
    assert_eq!(&pt, b"msg-1");
}
