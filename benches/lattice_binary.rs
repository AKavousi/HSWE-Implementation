use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use hswe_implementation::lattice::api::{Tag, decrypt, encrypt, evaluate_xor, extract};

const BATCH_SIZES: [usize; 5] = [1, 8, 32, 128, 512];

fn binary_lattice_benchmarks(criterion: &mut Criterion) {
    let tag = Tag::new(b"benchmark:lattice-binary:epoch-42");
    let witness = extract(&tag);

    let mut encrypt_group = criterion.benchmark_group("lattice_binary_encrypt");

    encrypt_group.bench_function("one_bit", |bencher| {
        let mut nonce = 0_u64;

        bencher.iter(|| {
            nonce = nonce.wrapping_add(1);

            black_box(encrypt(
                black_box((nonce & 1) == 1),
                black_box(&tag),
                black_box(nonce),
            ))
        });
    });

    encrypt_group.finish();

    let inputs: Vec<_> = BATCH_SIZES
        .into_iter()
        .map(|batch_size| {
            let ciphertexts: Vec<_> = (0..batch_size)
                .map(|index| encrypt(index % 2 == 1, &tag, index as u64 + 1_000))
                .collect();

            let aggregate =
                evaluate_xor(&ciphertexts).expect("benchmark inputs are encrypted under one tag");

            (batch_size, ciphertexts, aggregate)
        })
        .collect();

    let mut aggregate_group = criterion.benchmark_group("lattice_binary_aggregate");

    for (batch_size, ciphertexts, _) in &inputs {
        aggregate_group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            ciphertexts,
            |bencher, ciphertexts| {
                bencher.iter(|| {
                    black_box(
                        evaluate_xor(black_box(ciphertexts))
                            .expect("benchmark inputs are encrypted under one tag"),
                    )
                });
            },
        );
    }

    aggregate_group.finish();

    let mut decrypt_group = criterion.benchmark_group("lattice_binary_aggregate_decrypt");

    for (batch_size, _, aggregate) in &inputs {
        decrypt_group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            aggregate,
            |bencher, aggregate| {
                bencher.iter(|| {
                    black_box(
                        decrypt(black_box(aggregate), black_box(&tag), black_box(&witness))
                            .expect("tag matches aggregate"),
                    )
                });
            },
        );
    }

    decrypt_group.finish();

    let mut naive_group = criterion.benchmark_group("lattice_binary_naive_decrypt");

    for (batch_size, ciphertexts, _) in &inputs {
        naive_group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            ciphertexts,
            |bencher, ciphertexts| {
                bencher.iter(|| {
                    let parity = ciphertexts.iter().fold(false, |accumulator, ciphertext| {
                        accumulator
                            ^ decrypt(black_box(ciphertext), black_box(&tag), black_box(&witness))
                                .expect("tag matches ciphertext")
                    });

                    black_box(parity)
                });
            },
        );
    }

    naive_group.finish();
}

criterion_group!(benches, binary_lattice_benchmarks);
criterion_main!(benches);
