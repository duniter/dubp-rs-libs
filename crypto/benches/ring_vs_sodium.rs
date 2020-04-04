use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ring::signature::{Ed25519KeyPair as RingKeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sodiumoxide::crypto::sign::{
    ed25519::{PublicKey, SecretKey, Seed as SodiumSeed, Signature},
    keypair_from_seed, sign_detached, verify_detached,
};

const MESSAGE: &[u8] = b"azedjlazifjs dleufxmjz jfmjfmljrfmlgc jzlamu^^^^^^^^^^^^^^^^^^^^^ssssssssssssssssssssssss\
ssssssssssssszaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa541368630...5.31873679387azqszxdxs<dzdq ccg ill:;n: \
!   gjbtirglkrtnjbgkgbrl gjbtirglkrtnjbgkgbrl:lqjczo jlnkrhilhloiemoipo cjiothurhtgilrjumloc impiorjtiyhlilu*u*^&&";

fn ring_sign(ring_key_pair: &RingKeyPair) {
    ring_key_pair.sign(MESSAGE);
}

fn ring_verify((ring_key_pair, signature): (&RingKeyPair, &[u8])) {
    UnparsedPublicKey::new(&ED25519, ring_key_pair.public_key())
        .verify(MESSAGE, signature)
        .expect("invalid sig");
}

fn sodium_sign(sodium_secret_key: &SecretKey) {
    let _ = sign_detached(MESSAGE, &sodium_secret_key);
}

fn sodium_verify((public_key, signature): (&PublicKey, &Signature)) {
    assert!(verify_detached(signature, MESSAGE, public_key))
}

pub fn benchmark(c: &mut Criterion) {
    // Generate keypair
    let seed = dup_crypto::rand::gen_32_bytes().expect("fail to gen random seed");
    let ring_key_pair =
        RingKeyPair::from_seed_unchecked(seed.as_ref()).expect("fail to gen ring keypair");
    let (sodium_public_key, sodium_secret_key) = keypair_from_seed(&SodiumSeed(seed));

    // Sign benches
    let mut group = c.benchmark_group("sign");
    group.bench_function("sodium_sign", |b| {
        b.iter(|| sodium_sign(black_box(&sodium_secret_key)))
    });
    group.bench_function("ring_sign", |b| {
        b.iter(|| ring_sign(black_box(&ring_key_pair)))
    });
    group.finish();

    // Generate signature
    let ring_sig = ring_key_pair.sign(MESSAGE);
    let sodium_sig = sign_detached(MESSAGE, &sodium_secret_key);

    // Verify benches
    let mut group = c.benchmark_group("verify");
    group.bench_function("sodium_verify", |b| {
        b.iter(|| sodium_verify(black_box((&sodium_public_key, &sodium_sig))))
    });
    group.bench_function("ring_verify", |b| {
        b.iter(|| ring_verify(black_box((&ring_key_pair, ring_sig.as_ref()))))
    });
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
