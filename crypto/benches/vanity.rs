use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ring::signature::{Ed25519KeyPair as RingKeyPair, KeyPair};

fn gen_1000_pubkeys(seed: &[u8; 32]) {
    let mut seed = *seed;

    for i in 0..1_000 {
        let kp = RingKeyPair::from_seed_unchecked(&seed).expect("fail to gen keypair");
        let pk = kp.public_key();
        let mut buffer = [0u8; 44];
        bs58::encode(pk)
            .into(&mut buffer[..])
            .expect("fail to encode pubkey");
        let pk58 = unsafe { std::str::from_utf8_unchecked(&buffer[..]) };
        if pk58.starts_with("toto") {
            println!("{}", pk58);
        }
        let x = i % 32;
        seed[x] = seed[x].overflowing_add(1).0;
    }
}

pub fn benchmark(c: &mut Criterion) {
    // Generate keypair
    let seed = dup_crypto::rand::gen_32_bytes().expect("fail to gen random seed");

    // Sign benches
    let mut group = c.benchmark_group("g1");
    group.bench_function("gen_1000_pubkeys", |b| {
        b.iter(|| gen_1000_pubkeys(black_box(&seed)))
    });
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
