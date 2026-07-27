use std::{
    fs::{File, create_dir_all},
    io::Write,
    time::{Duration, Instant},
};

use hswe_implementation::{
    aggregation::aggregate_cross_tag, decryption::decrypt_cross_tag_aggregate, encryption::encrypt,
    keys::HsweSecretKey, lookup::TargetLookupTable, params::HsweParameters, tag::Tag,
};

const SAMPLES: usize = 100;
const BATCH_SIZES: [usize; 5] = [1, 8, 32, 128, 512];

fn mean_ms(samples: &[Duration]) -> f64 {
    let total_seconds: f64 = samples.iter().map(Duration::as_secs_f64).sum();
    (total_seconds / samples.len() as f64) * 1_000.0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all("results")?;
    let mut csv = File::create("results/cross_tag_times.csv")?;

    writeln!(
        csv,
        "tag_count,aggregate_ms,cross_tag_decrypt_ms,naive_decrypt_ms,speedup"
    )?;

    // Each ciphertext encrypts a value in 0..=100. At 512 tags, the largest
    // possible aggregate is 51,200, which fits into the aggregate lookup table.
    let parameters = HsweParameters::new(100, 65_535)?;

    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let lookup_table = TargetLookupTable::new(
        parameters.parameter_id(),
        parameters.aggregate_message_max(),
    )?;

    for tag_count in BATCH_SIZES {
        let mut aggregate_times = Vec::with_capacity(SAMPLES);
        let mut cross_tag_decrypt_times = Vec::with_capacity(SAMPLES);
        let mut naive_decrypt_times = Vec::with_capacity(SAMPLES);

        for sample in 0..SAMPLES {
            let tags = (0..tag_count)
                .map(|i| Tag::epoch("cross-tag-benchmark", (sample * tag_count + i) as u64 + 1))
                .collect::<Result<Vec<_>, _>>()?;

            let messages: Vec<u64> = (0..tag_count)
                .map(|i| ((sample + i) % 101) as u64)
                .collect();

            let expected_total: u64 = messages.iter().sum();

            let signatures = tags
                .iter()
                .map(|tag| secret_key.sign(tag))
                .collect::<Vec<_>>();

            let ciphertexts = tags
                .iter()
                .zip(messages.iter())
                .map(|(tag, &message)| encrypt(&parameters, &public_key, tag.clone(), message))
                .collect::<Result<Vec<_>, _>>()?;

            let aggregate_start = Instant::now();

            let aggregate = aggregate_cross_tag(&parameters, &ciphertexts)?;

            aggregate_times.push(aggregate_start.elapsed());

            let cross_tag_decrypt_start = Instant::now();

            let recovered_total = decrypt_cross_tag_aggregate(
                &parameters,
                &public_key,
                &aggregate,
                &signatures,
                &lookup_table,
            )?;

            cross_tag_decrypt_times.push(cross_tag_decrypt_start.elapsed());

            assert_eq!(recovered_total, expected_total);

            let naive_decrypt_start = Instant::now();

            let mut naive_total = 0u64;

            for ((ciphertext, signature), expected_message) in ciphertexts
                .iter()
                .zip(signatures.iter())
                .zip(messages.iter())
            {
                let recovered = hswe_implementation::decryption::decrypt(
                    &parameters,
                    &public_key,
                    ciphertext,
                    signature,
                    &lookup_table,
                )?;

                assert_eq!(recovered, *expected_message);

                naive_total = naive_total
                    .checked_add(recovered)
                    .ok_or("naive sum overflow")?;
            }

            naive_decrypt_times.push(naive_decrypt_start.elapsed());

            assert_eq!(naive_total, expected_total);
        }

        let aggregate_ms = mean_ms(&aggregate_times);
        let cross_tag_decrypt_ms = mean_ms(&cross_tag_decrypt_times);
        let naive_decrypt_ms = mean_ms(&naive_decrypt_times);

        let speedup = naive_decrypt_ms / cross_tag_decrypt_ms;

        writeln!(
            csv,
            "{tag_count},{aggregate_ms:.6},{cross_tag_decrypt_ms:.6},\
             {naive_decrypt_ms:.6},{speedup:.3}"
        )?;

        println!(
            "{tag_count:4} tags | aggregate {aggregate_ms:8.3} ms | \
             cross-tag decrypt {cross_tag_decrypt_ms:8.3} ms | \
             naive decrypt {naive_decrypt_ms:8.3} ms | \
             speedup {speedup:6.2}x"
        );
    }

    println!("\nWrote results/cross_tag_times.csv");
    Ok(())
}
