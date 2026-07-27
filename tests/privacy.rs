use ark_bls12_381::Fr;
use ark_ff::Zero;

use hswe_implementation::{
    aggregation::aggregate_same_tag,
    decryption::{decrypt, decrypt_same_tag_aggregate},
    encryption::encrypt,
    keys::HsweSecretKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
    privacy::{blind_ciphertext, remove_aggregate_blind, sample_blind},
    sharing::{reconstruct_secret, split_secret},
    tag::Tag,
};

#[test]
fn private_same_tag_tally_recovers_only_the_total() {
    let parameters = HsweParameters::new(100, 100).unwrap();

    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let tag = Tag::epoch("private-tally-test", 1).unwrap();
    let signature = secret_key.sign(&tag);

    let lookup_table =
        TargetLookupTable::new(parameters.parameter_id(), 100).unwrap();

    let messages = [4u64, 7u64, 12u64];
    let expected_total: u64 = messages.iter().sum();

    let mut blinded_ciphertexts = Vec::new();
    let mut aggregate_blind = Fr::zero();

    for message in messages {
        let ciphertext =
            encrypt(&parameters, &public_key, tag.clone(), message).unwrap();

        let blind = sample_blind();
        aggregate_blind += blind;

        let shares = split_secret(blind, 2, 3).unwrap();
        let reconstructed_blind = reconstruct_secret(&shares[..2], 2).unwrap();

        assert_eq!(reconstructed_blind, blind);

        let blinded = blind_ciphertext(&ciphertext, blind);

        assert!(
            decrypt(
                &parameters,
                &public_key,
                &blinded,
                &signature,
                &lookup_table,
            )
            .is_err(),
            "a blinded individual ciphertext must not baseline-decrypt"
        );

        blinded_ciphertexts.push(blinded);
    }

    let blinded_aggregate =
        aggregate_same_tag(&parameters, &blinded_ciphertexts).unwrap();

    let unblinded_aggregate =
        remove_aggregate_blind(&blinded_aggregate, aggregate_blind);

    let recovered_total = decrypt_same_tag_aggregate(
        &parameters,
        &public_key,
        &unblinded_aggregate,
        &signature,
        &lookup_table,
    )
    .unwrap();

    assert_eq!(recovered_total, expected_total);
}