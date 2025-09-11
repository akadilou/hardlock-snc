use hardlock_snc::crypto::hpke_hybrid::{hpke_accept, hpke_initiate};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;
use hardlock_snc::session::Session;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let alice = DeviceIdentity::generate("alice".into(), "phone".into());
    let bob = DeviceIdentity::generate("bob".into(), "laptop".into());

    let (enc, s_a) = hpke_initiate(&bob.x25519.public())?;
    let s_b = hpke_accept(&bob.x25519.sk.clone().try_into().unwrap(), &enc)?;

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

    let ad = b"hardlock/persist";
    let (h, n, ct) = ratchet::encrypt(&mut ra, ad, b"first");
    let pt = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).expect("decrypt");
    println!("Bob got: {}", String::from_utf8_lossy(&pt));

    let dir_a = PathBuf::from("/tmp/hl_alice");
    let dir_b = PathBuf::from("/tmp/hl_bob");
    std::fs::create_dir_all(&dir_a).ok();
    std::fs::create_dir_all(&dir_b).ok();

    let sa = Session::new("alice->bob".into(), ra);
    let sb = Session::new("bob->alice".into(), rb);
    sa.save_fs(dir_a.to_str().unwrap(), "pass")?;
    sb.save_fs(dir_b.to_str().unwrap(), "pass")?;

    let mut sa2 = Session::load_fs(dir_a.to_str().unwrap(), "pass", "alice->bob")?;
    let mut sb2 = Session::load_fs(dir_b.to_str().unwrap(), "pass", "bob->alice")?;

    let (h2, n2, ct2) = ratchet::encrypt(&mut sa2.state, ad, b"second");
    let pt2 = ratchet::decrypt(&mut sb2.state, ad, &h2, &n2, &ct2).expect("decrypt");
    println!("Bob got: {}", String::from_utf8_lossy(&pt2));

    Ok(())
}
