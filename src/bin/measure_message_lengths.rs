use std::{
    fs::{create_dir_all, File},
    io::Write,
    time::{Duration, Instant},
};

use hswe_implementation::{
    decryption::decrypt,
    encryption::encrypt,
    keys::HsweSecretKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
    tag::Tag,
};

const SAMPLES: usize = 1_000;
const MAX_MESSAGE_BITS: u32 = 16;

fn mean_ms(samples: &[Duration]) -> f64 {
    let total_seconds: f64 = samples.iter().map(Duration::as_secs_f64).sum();
    (total_seconds / samples.len() as f64) * 1_000.0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all("results")?;
    let mut csv = File::create("results/message_length_times.csv")?;

    writeln!(
        csv,
        "message_bits,encryption_mean_ms,decryption_mean_ms"
    )?;

    // IMPORTANT:
    // Adjust this constructor if your HsweParameters API uses another name
    // or needs values supplied explicitly.
    let parameters = HsweParameters::new(65_535, 65_535)?;

    // One key pair, tag, witness/signature, and lookup table for all trials.
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    // Adjust this constructor if Tag has a different API.
    let tag = Tag::epoch("message-length-benchmark", 1)?;

    let signature = secret_key.sign(&tag);

    // The lookup table must cover every plaintext value tested:
    // maximum 16-bit plaintext = 2^16 - 1 = 65,535.
    //
    // Adjust this constructor if TargetLookupTable uses another API.
    let lookup_table = TargetLookupTable::new(
        parameters.parameter_id(),
        parameters.individual_message_max(),
    )?;

    for bits in 0..=MAX_MESSAGE_BITS {
        let upper_bound = 1_u64 << bits;

        let mut encryption_times = Vec::with_capacity(SAMPLES);
        let mut decryption_times = Vec::with_capacity(SAMPLES);

        for sample in 0..SAMPLES {
            let message = (sample as u64) % upper_bound;

            let encryption_start = Instant::now();

            let ciphertext = encrypt(
                &parameters,
                &public_key,
                tag.clone(),
                message,
            )?;

            encryption_times.push(encryption_start.elapsed());

            let decryption_start = Instant::now();

            let recovered = decrypt(
                &parameters,
                &public_key,
                &ciphertext,
                &signature,
                &lookup_table,
            )?;

            decryption_times.push(decryption_start.elapsed());

            assert_eq!(
                recovered, message,
                "incorrect recovery for {bits}-bit plaintext {message}"
            );
        }

        let encryption_ms = mean_ms(&encryption_times);
        let decryption_ms = mean_ms(&decryption_times);

        writeln!(
            csv,
            "{bits},{encryption_ms:.6},{decryption_ms:.6}"
        )?;

        println!(
            "{bits:2} bits | encryption: {encryption_ms:8.4} ms | \
             decryption: {decryption_ms:8.4} ms"
        );
    }

    println!("\nWrote results/message_length_times.csv");
    Ok(())
}