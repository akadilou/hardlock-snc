use hardlock_snc::crypto::hpke_hybrid::{hpke_accept, hpke_initiate_deterministic};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::ratchet;
use serde::Serialize;

#[derive(Serialize)]
struct HpkeKat {
    seed: [u8; 32],
    enc: String,
    okm: String,
}
#[derive(Serialize)]
struct Msg {
    header: String,
    nonce: String,
    ct: String,
}
#[derive(Serialize)]
struct RatchetKat {
    ad: String,
    msgs: Vec<Msg>,
}

fn hex(x: &[u8]) -> String {
    {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(x.len() * 2);
        for &b in x {
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

fn main() -> anyhow::Result<()> {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());
    let seed = [42u8; 32];
    let (enc, okm_a) = hpke_initiate_deterministic(&b.x25519.public(), seed)?;
    let okm_b = hpke_accept(&b.x25519.sk.clone().try_into().unwrap(), &enc)?;
    assert_eq!(okm_a, okm_b);
    let hpke = HpkeKat {
        seed,
        enc: hex(&enc),
        okm: hex(&okm_a),
    };
    std::fs::write("KATS/hpke_base.json", serde_json::to_vec_pretty(&hpke)?)?;

    let mut ra = ratchet::init_initiator(
        okm_a,
        a.x25519.sk.clone().try_into().unwrap(),
        b.x25519.public(),
    );
    let mut rb = ratchet::init_responder(
        okm_b,
        b.x25519.sk.clone().try_into().unwrap(),
        a.x25519.public(),
    );
    let ad = b"kat/ad";
    let mut out = Vec::new();
    for i in 0..5u8 {
        let (h, n, ct) = ratchet::encrypt(&mut ra, ad, &[i; 16]);
        let _ = ratchet::decrypt(&mut rb, ad, &h, &n, &ct).unwrap();
        out.push(Msg {
            header: hex(&[&h.dh_pub[..], &h.pn.to_le_bytes(), &h.n.to_le_bytes()].concat()),
            nonce: hex(&n),
            ct: hex(&ct),
        });
    }
    let rkat = RatchetKat {
        ad: "kat/ad".into(),
        msgs: out,
    };
    std::fs::write("KATS/ratchet.json", serde_json::to_vec_pretty(&rkat)?)?;
    Ok(())
}
