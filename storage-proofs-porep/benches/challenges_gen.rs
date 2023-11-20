use blstrs::Scalar as Fr;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ff::Field;
use filecoin_hashers::{
    sha256::{Sha256Domain, Sha256Hasher},
    Domain, Hasher,
};
use fr32::fr_into_bytes;
use num_bigint::BigUint;
use rand::thread_rng;
use storage_proofs_core::{api_version::ApiVersion, util::NODE_SIZE};
use storage_proofs_porep::stacked::{
    create_label::single::{create_label, create_label_exp},
    NiChallenges, NiChallengesChaCha, StackedBucketGraph,
};

fn challenges_generation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("challenges");
    group.sample_size(10);

    group.bench_function("ni-sha256", |b| {
        let challenges = NiChallenges::new(18);
        let sector_nodes = 32 * 1024 * 1024 * 1024 / NODE_SIZE;
        let replica_id = [1u8; 32];
        let comm_r = [2u8; 32];
        let k = 80;
        b.iter(|| {
            black_box(challenges.derive::<Sha256Domain>(
                sector_nodes,
                &replica_id.into(),
                &comm_r.into(),
                k,
            ))
        })
    });

    group.bench_function("ni-chacha20", |b| {
        let challenges = NiChallengesChaCha::new(18);
        let sector_nodes = 32 * 1024 * 1024 * 1024 / NODE_SIZE;
        let replica_id = [1u8; 32];
        let comm_r = [2u8; 32];
        let k = 80;
        b.iter(|| {
            black_box(challenges.derive::<Sha256Domain>(
                sector_nodes,
                &replica_id.into(),
                &comm_r.into(),
                k,
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, challenges_generation_benchmark);
criterion_main!(benches);
