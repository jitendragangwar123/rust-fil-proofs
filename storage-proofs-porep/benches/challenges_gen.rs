use blstrs::Scalar as Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ff::Field;
use filecoin_hashers::{
    sha256::{Sha256Domain, Sha256Hasher},
    Domain, Hasher,
};
use fr32::fr_into_bytes;
use rand::thread_rng;
use storage_proofs_core::{api_version::ApiVersion, util::NODE_SIZE};
use storage_proofs_porep::stacked::{
    create_label::single::{create_label, create_label_exp},
    NiChallenges, StackedBucketGraph,
};

fn challenges_generation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("challenges");
    group.sample_size(10);
    //group.throughput(Throughput::Bytes(
    //    /* replica id + 37 parents + node id */ 39 * 32,
    //));

    group.bench_function("ni-sha256", |b| {
        let challenges = NiChallenges::new(18);
        let sector_nodes = 32 * 1024 * 1024 * 1024 / NODE_SIZE;
        let replica_id = [1u8; 32];
        let comm_r = [2u8; 32];
        let k = 126;
        b.iter(|| {
            black_box(challenges.derive::<Sha256Domain>(
                sector_nodes,
                &replica_id.into(),
                &comm_r.into(),
                k,
            ))
        })
    });

    //group.bench_function("non-exp", |b| {
    //    let mut data = data.clone();
    //    let graph = &graph;
    //
    //    b.iter(|| black_box(create_label(graph, None, replica_id, &mut data, 1, 2)))
    //});

    group.finish();
}

criterion_group!(benches, challenges_generation_benchmark);
criterion_main!(benches);
