use argon2::{Algorithm, Argon2, Params, Version};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_argon(c: &mut Criterion) {
    let pass = b"bench-passphrase";
    let salt = b"hardlock-salt-16-bytes";
    let mut out = [0u8; 32];

    let profiles = [
        ("FAST", 64 * 1024, 3, 1),
        ("BALANCED", 256 * 1024, 3, 1),
        ("STRONG", 1024 * 1024, 3, 1),
    ];

    for (name, m_cost, t_cost, p_cost) in profiles {
        c.bench_function(&format!("argon2id_{}", name), |ben| {
            ben.iter(|| {
                let params = Params::new(m_cost, t_cost, p_cost, Some(out.len())).unwrap();
                let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                a2.hash_password_into(black_box(pass), black_box(salt), &mut out)
                    .unwrap();
            })
        });
    }
}
criterion_group!(benches, bench_argon);
criterion_main!(benches);
