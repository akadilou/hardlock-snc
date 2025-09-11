use hardlock_snc::crypto::hpke_hybrid::{hpke_accept_with_binder, hpke_initiate_with_binder};
use hardlock_snc::envelope::{apply_padding, derive_k_s, token_build, token_verify, PadProfile};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;
use hardlock_snc::suites;
use hardlock_snc::wire::{pack_message, unpack_message};
use hardlock_snc::HL_VERSION;

fn main() -> anyhow::Result<()> {
    let alice = DeviceIdentity::generate("alice".into(), "phone".into());
    let bob = DeviceIdentity::generate("bob".into(), "laptop".into());

    let (enc, s_a, binder) = hpke_initiate_with_binder(&bob.x25519.public(), suites::HL1_BASE)?;
    let s_b = hpke_accept_with_binder(
        suites::HL1_BASE,
        &bob.x25519.sk.clone().try_into().unwrap(),
        &enc,
        &binder,
    )?;

    let mut ra = ratchet::init_initiator(
        s_a,
        alice.x25519.sk.clone().try_into().unwrap(),
        bob.x25519.public(),
    );
    let mut rb = ratchet::init_responder(
        s_b,
        bob.x25519.sk.clone().try_into().unwrap(),
        alice.x25519.public(),
    );

    let master = [9u8; 32];
    let k_s = derive_k_s(&master, b"salt");
    let token = token_build(&k_s, 4102444800, &alice.x25519.public(), b"chat");

    let ad = b"env/pipeline";
    let (h, n, ct) = ratchet::encrypt(&mut ra, ad, b"hello");
    let frame = pack_message(HL_VERSION, &h, &n, &ct, 1);
    let framed = apply_padding(frame, PadProfile::Balanced);

    let _tv = token_verify(&k_s, &token, 4100000000).ok_or_else(|| anyhow::anyhow!("bad token"))?;

    let (_ver, hh, nn, cc) = unpack_message(&framed)?;
    let pt = ratchet::decrypt(&mut rb, ad, &hh, &nn, &cc)?;
    println!("{}", String::from_utf8_lossy(&pt));
    Ok(())
}
