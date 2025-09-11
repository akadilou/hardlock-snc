use clap::Parser;
use hardlock_snc::crypto::hpke_hybrid::{hpke_accept, hpke_initiate};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value_t = 3)]
    rounds: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let alice = DeviceIdentity::generate("alice".into(), "alice-phone".into());
    let bob = DeviceIdentity::generate("bob".into(), "bob-laptop".into());
    let (enc, s_a) = hpke_initiate(&bob.x25519.public())?;
    let s_b = hpke_accept(&bob.x25519.sk.clone().try_into().unwrap(), &enc)?;
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
    let ad = b"hardlock/example";
    for i in 0..args.rounds {
        let (h, n, ct) = ratchet::encrypt(
            &mut r_alice,
            ad,
            format!("Hello {} from Alice", i).as_bytes(),
        );
        let pt = ratchet::decrypt(&mut r_bob, ad, &h, &n, &ct)
            .map_err(|_| anyhow::anyhow!("decrypt"))?;
        println!("Bob got: {}", String::from_utf8_lossy(&pt));
        let (h2, n2, ct2) =
            ratchet::encrypt(&mut r_bob, ad, format!("Ack {} from Bob", i).as_bytes());
        let pt2 = ratchet::decrypt(&mut r_alice, ad, &h2, &n2, &ct2)
            .map_err(|_| anyhow::anyhow!("decrypt"))?;
        println!("Alice got: {}", String::from_utf8_lossy(&pt2));
    }
    Ok(())
}
