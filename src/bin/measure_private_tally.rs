use std::{
    fs::{create_dir_all, File},
    io::Write,
    time::{Duration, Instant},
};

use ark_bls12_381::Fr;
use ark_ff::Zero;

use hswe_implementation::{
    aggregation::aggregate_same_tag,
    decryption::decrypt_same_tag_aggregate,
    encryption::encrypt,
    keys::HsweSecretKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
    privacy::{blind_ciphertext, remove_aggregate_blind, sample_blind},
    sharing::{reconstruct_secret, split_secret, ScalarShare},
    tag::Tag,
};

const SAMPLES: usize = 100;
const COMMITTEE_SIZE: usize = 3;
const THRESHOLD: usize = 2;
const BATCH_SIZES: [usize; 5] = [1, 8, 32, 128, 512];

fn mean_ms(samples: &[Duration]) -> f64 {
    let total_seconds: f64 = samples.iter().map(Duration::as_secs_f64).sum();
    (total_seconds / samples.len() as f64) * 1_000.0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all("results")?;
    let mut csv = File::create("results/private_tally_times.csv")?;

    writeln!(
        csv,
        "batch_size,blind_each_ms,aggregate_ms,reconstruct_ms,unblind_ms,decrypt_ms,total_ms"
    )?;

    let parameters = HsweParameters::new(100, 65_535)?;
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let tag = Tag::epoch("private-tally-benchmark", 1)?;
    let signature = secret_key.sign(&tag);

    let lookup_table = TargetLookupTable::new(
        parameters.parameter_id(),
        parameters.aggregate_message_max(),
    )?;

    for batch_size in BATCH_SIZES {
        let mut blind_each_times = Vec::with_capacity(SAMPLES);
        let mut aggregate_times = Vec::with_capacity(SAMPLES);
        let mut reconstruct_times = Vec::with_capacity(SAMPLES);
        let mut unblind_times = Vec::with_capacity(SAMPLES);
        let mut decrypt_times = Vec::with_capacity(SAMPLES);

        for sample in 0..SAMPLES {
            let messages: Vec<u64> = (0..batch_size)
                .map(|i| ((sample + i) % 101) as u64)
                .collect();

            let expected_total: u64 = messages.iter().sum();

            let ciphertexts = messages
                .iter()
                .map(|&message| encrypt(&parameters, &public_key, tag.clone(), message))
                .collect::<Result<Vec<_>, _>>()?;

            let blind_start = Instant::now();

            let mut blinded_ciphertexts = Vec::with_capacity(batch_size);
            let mut committee_sums = vec![Fr::zero(); COMMITTEE_SIZE];

            for ciphertext in &ciphertexts {
                let blind = sample_blind();
                let shares = split_secret(blind, THRESHOLD, COMMITTEE_SIZE)?;

                for (committee_sum, share) in committee_sums.iter_mut().zip(&shares) {
                    *committee_sum += share.value();
                }

                blinded_ciphertexts.push(blind_ciphertext(ciphertext, blind));
            }

            blind_each_times.push(blind_start.elapsed());

            let aggregate_start = Instant::now();

            let blinded_aggregate =
                aggregate_same_tag(&parameters, &blinded_ciphertexts)?;

            aggregate_times.push(aggregate_start.elapsed());

            let reconstruct_start = Instant::now();

            let aggregate_shares = committee_sums
                .iter()
                .enumerate()
                .map(|(i, &value)| ScalarShare::new((i + 1) as u64, value))
                .collect::<Result<Vec<_>, _>>()?;

            let aggregate_blind =
                reconstruct_secret(&aggregate_shares[..THRESHOLD], THRESHOLD)?;

            reconstruct_times.push(reconstruct_start.elapsed());

            let unblind_start = Instant::now();

            let unblinded_aggregate =
                remove_aggregate_blind(&blinded_aggregate, aggregate_blind);

            unblind_times.push(unblind_start.elapsed());

            let decrypt_start = Instant::now();

            let recovered_total = decrypt_same_tag_aggregate(
                &parameters,
                &public_key,
                &unblinded_aggregate,
                &signature,
                &lookup_table,
            )?;

            decrypt_times.push(decrypt_start.elapsed());

            assert_eq!(recovered_total, expected_total);
        }

        let blind_each_ms = mean_ms(&blind_each_times);
        let aggregate_ms = mean_ms(&aggregate_times);
        let reconstruct_ms = mean_ms(&reconstruct_times);
        let unblind_ms = mean_ms(&unblind_times);
        let decrypt_ms = mean_ms(&decrypt_times);
        let total_ms =
            blind_each_ms + aggregate_ms + reconstruct_ms + unblind_ms + decrypt_ms;

        writeln!(
            csv,
            "{batch_size},{blind_each_ms:.6},{aggregate_ms:.6},\
             {reconstruct_ms:.6},{unblind_ms:.6},{decrypt_ms:.6},{total_ms:.6}"
        )?;

        println!(
            "{batch_size:4} ciphertexts | blind {blind_each_ms:8.3} ms | \
             aggregate {aggregate_ms:8.3} ms | reconstruct {reconstruct_ms:8.3} ms | \
             unblind {unblind_ms:8.3} ms | decrypt {decrypt_ms:8.3} ms | \
             total {total_ms:8.3} ms"
        );
    }

    println!("\nWrote results/private_tally_times.csv");
    Ok(())
}