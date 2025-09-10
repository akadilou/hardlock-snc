use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::crypto::hpke_hybrid::hpke_initiate;
use hardlock_snc::ratchet;
use proptest::prelude::*;

proptest! {
  #[test]
  fn roundtrip_random(msg in proptest::collection::vec(any::<u8>(), 0..4096)) {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let (enc, s_a) = hpke_initiate(&b.x25519.public()).unwrap();
    let s_b = hardlock_snc::crypto::hpke_hybrid::hpke_accept(&b.x25519.sk.clone().try_into().unwrap(), &enc).unwrap();
    let mut ra = ratchet::init_initiator(s_a, a.x25519.sk.clone().try_into().unwrap(), b.x25519.public());
    let mut rb = ratchet::init_responder(s_b, b.x25519.sk.clone().try_into().unwrap(), a.x25519.public());
    let ad = b"ad";
    let (h, n, ct) = ratchet::encrypt(&mut ra, ad, &msg);
    let pt = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).unwrap();
    prop_assert_eq!(pt, msg);
  }
}

proptest! {
  #[test]
  fn out_of_order_same_chain(msgs in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 2..8)) {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let (enc, s_a) = hpke_initiate(&b.x25519.public()).unwrap();
    let s_b = hardlock_snc::crypto::hpke_hybrid::hpke_accept(&b.x25519.sk.clone().try_into().unwrap(), &enc).unwrap();
    let mut ra = ratchet::init_initiator(s_a, a.x25519.sk.clone().try_into().unwrap(), b.x25519.public());
    let mut rb = ratchet::init_responder(s_b, b.x25519.sk.clone().try_into().unwrap(), a.x25519.public());
    let ad = b"ad";
    let mut bufs = Vec::new();
    for m in &msgs {
      bufs.push(ratchet::encrypt(&mut ra, ad, m));
    }
    // On livre dans l'ordre inverse
    for (i, (h,n,ct)) in bufs.into_iter().rev().enumerate() {
      let pt = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).unwrap();
      let exp = &msgs[msgs.len()-1-i];
      prop_assert_eq!(&pt, exp);
    }
  }
}
