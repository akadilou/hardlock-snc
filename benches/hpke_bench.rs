use criterion::{criterion_group, criterion_main, Criterion, black_box};
use hardlock_snc::identity::DeviceIdentity;
use hardlock_snc::crypto::hpke_hybrid::{hpke_initiate, hpke_accept, hpke_initiate_auth, hpke_accept_auth};

fn bench_hpke(c: &mut Criterion) {
    let a = DeviceIdentity::generate("a".into(), "d1".into());
    let b = DeviceIdentity::generate("b".into(), "d2".into());

    c.bench_function("hpke_base_initiate", |ben| {
        ben.iter(|| { let _ = hpke_initiate(black_box(&b.x25519.public())).unwrap(); })
    });

    c.bench_function("hpke_base_accept", |ben| {
        let (enc, _) = hpke_initiate(&b.x25519.public()).unwrap();
        ben.iter(|| { let _ = hpke_accept(black_box(&b.x25519.sk.clone().try_into().unwrap()), black_box(&enc)).unwrap(); })
    });

    c.bench_function("hpke_auth_initiate", |ben| {
        ben.iter(|| {
            let _ = hpke_initiate_auth(
                black_box(&a.x25519.sk.clone().try_into().unwrap()),
                black_box(&b.x25519.public()),
            ).unwrap();
        })
    });

    c.bench_function("hpke_auth_accept", |ben| {
        let (enc, _) = hpke_initiate_auth(&a.x25519.sk.clone().try_into().unwrap(), &b.x25519.public()).unwrap();
        ben.iter(|| {
            let _ = hpke_accept_auth(
                black_box(&a.x25519.public()),
                black_box(&b.x25519.sk.clone().try_into().unwrap()),
                black_box(&enc),
            ).unwrap();
        })
    });
}
criterion_group!(benches, bench_hpke);
criterion_main!(benches);
