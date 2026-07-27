use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use hswe_implementation::{
    aggregation::aggregate_same_tag,
    decryption::{decrypt, decrypt_same_tag_aggregate},
    encryption::encrypt,
    keys::HsweSecretKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
    tag::Tag,
};

fn benchmark_same_tag(c: &mut Criterion) {
    let parameters = HsweParameters::new(20, 100).expect("valid parameters");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();
    let tag = Tag::epoch("benchmark/same-tag", 1).expect("valid tag");
    let signature = secret_key.sign(&tag);
    let lookup =
        TargetLookupTable::new(parameters.parameter_id(), 20_000).expect("valid lookup table");

    let mut group = c.benchmark_group("same_tag");

    for batch_size in [1usize, 8, 32, 128, 512] {
        let ciphertexts: Vec<_> = (0..batch_size)
            .map(|_| encrypt(&parameters, &public_key, tag.clone(), 1).expect("encrypt"))
            .collect();

        let aggregate = aggregate_same_tag(&parameters, &ciphertexts).expect("aggregate");

        group.bench_with_input(
            BenchmarkId::new("aggregate", batch_size),
            &ciphertexts,
            |b, ciphertexts| {
                b.iter(|| {
                    aggregate_same_tag(black_box(&parameters), black_box(ciphertexts))
                        .expect("aggregate")
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decrypt_aggregate", batch_size),
            &aggregate,
            |b, aggregate| {
                b.iter(|| {
                    decrypt_same_tag_aggregate(
                        black_box(&parameters),
                        black_box(&public_key),
                        black_box(aggregate),
                        black_box(&signature),
                        black_box(&lookup),
                    )
                    .expect("decrypt aggregate")
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("decrypt_naive", batch_size),
            &ciphertexts,
            |b, ciphertexts| {
                b.iter(|| {
                    let total: u64 = ciphertexts
                        .iter()
                        .map(|ciphertext| {
                            decrypt(
                                black_box(&parameters),
                                black_box(&public_key),
                                black_box(ciphertext),
                                black_box(&signature),
                                black_box(&lookup),
                            )
                            .expect("decrypt")
                        })
                        .sum();
                    black_box(total)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_same_tag);
criterion_main!(benches);
