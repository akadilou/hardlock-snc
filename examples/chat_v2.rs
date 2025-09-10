use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::crypto::hpke_hybrid::{hpke_initiate_with_binder, hpke_accept_with_binder};
use hardlock_snc::ratchet;
use hardlock_snc::suites;
use hardlock_snc::wire::handshake::{encode_init_v2, decode_init_v2};

fn main() -> anyhow::Result<()> {
    let alice = DeviceIdentity::generate("alice".into(), "phone".into());
    let bob   = DeviceIdentity::generate("bob".into(),   "laptop".into());

    let (enc, secret_alice, binder) = hpke_initiate_with_binder(&bob.x25519.public(), suites::HL1_BASE)?;
    let frame = encode_init_v2(suites::HL1_BASE, &enc, &binder);

    let (suite, enc2, binder2) = decode_init_v2(&frame)?;
    let secret_bob = hpke_accept_with_binder(suite, &bob.x25519.sk.clone().try_into().unwrap(), &enc2, &binder2)?;

    let mut r_alice = ratchet::init_initiator(secret_alice, alice.x25519.sk.clone().try_into().unwrap(), bob.x25519.public());
    let mut r_bob   = ratchet::init_responder(secret_bob,   bob.x25519.sk.clone().try_into().unwrap(), alice.x25519.public());

    let ad = b"hardlock/chat_v2";
    let (h, n, ct) = ratchet::encrypt(&mut r_alice, ad, b"hello");
    let pt = ratchet::decrypt(&mut r_bob, ad, &h, &n, &ct).map_err(|_| anyhow::anyhow!("decrypt"))?;
    println!("{}", String::from_utf8_lossy(&pt));
    Ok(())
}
