use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::crypto::hpke_hybrid::{hpke_initiate_with_binder, hpke_accept_with_binder};
use hardlock_snc::{ratchet, suites};
use hardlock_snc::wire::handshake::{encode_init_v2, decode_init_v2};
use rand::{rngs::StdRng, SeedableRng, seq::SliceRandom};

#[test]
fn sim_end_to_end_reorder() {
    let mut rng = StdRng::seed_from_u64(42);
    let alice = DeviceIdentity::generate("alice".into(), "phone".into());
    let bob   = DeviceIdentity::generate("bob".into(),   "laptop".into());

    let (enc, s_a, binder) = hpke_initiate_with_binder(&bob.x25519.public(), suites::HL1_BASE).unwrap();
    let frame = encode_init_v2(suites::HL1_BASE, &enc, &binder);
    let (suite, enc2, binder2) = decode_init_v2(&frame).unwrap();
    let s_b = hpke_accept_with_binder(suite, &bob.x25519.sk.clone().try_into().unwrap(), &enc2, &binder2).unwrap();
    assert_eq!(s_a, s_b);

    let mut ra = ratchet::init_initiator(s_a, alice.x25519.sk.clone().try_into().unwrap(), bob.x25519.public());
    let mut rb = ratchet::init_responder(s_b, bob.x25519.sk.clone().try_into().unwrap(), alice.x25519.public());

    let ad = b"sim/e2e";
    let mut msgs = Vec::new();
    for i in 0..64u32 {
        let m = format!("m{}", i);
        let (h, n, ct) = ratchet::encrypt(&mut ra, ad, m.as_bytes());
        msgs.push((h, n, ct));
    }
    msgs.shuffle(&mut rng);
    for (h, n, ct) in msgs {
        let pt = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).expect("decrypt");
        assert!(pt.starts_with(b"m"));
    }
}
