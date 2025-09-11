use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hardlock_snc::crypto::aeadx::{open_xchacha, rand_nonce, seal_xchacha, KEY_LEN};
use rand::RngCore;

fn bench_aead(c: &mut Criterion) {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);

    for &size in &[1024usize, 65536usize] {
        c.bench_function(&format!("xchacha_seal_{}B", size), |ben| {
            ben.iter_batched(
                || (vec![7u8; size], rand_nonce(), b"ad".to_vec()),
                |(pt, nonce, ad)| {
                    let _ = seal_xchacha(&key, &nonce, black_box(&pt), black_box(&ad));
                },
                BatchSize::SmallInput,
            )
        });

        c.bench_function(&format!("xchacha_open_{}B", size), |ben| {
            let pt = vec![7u8; size];
            let nonce = rand_nonce();
            let ad = b"ad".to_vec();
            let ct = seal_xchacha(&key, &nonce, &pt, &ad);
            ben.iter(|| {
                let _ = open_xchacha(&key, &nonce, black_box(&ct), black_box(&ad)).unwrap();
            })
        });
    }
}
criterion_group!(benches, bench_aead);
criterion_main!(benches);
