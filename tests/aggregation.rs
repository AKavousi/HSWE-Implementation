use ark_ec::{AffineRepr, CurveGroup};

use hswe_implementation::{
    aggregation::aggregate_same_tag, encryption::encrypt, error::HsweError, keys::HsweSecretKey,
    params::HsweParameters, tag::Tag,
};

fn test_tag(epoch: u64) -> Tag {
    Tag::epoch("aggregation-test", epoch).expect("tag must be valid")
}

#[test]
fn same_tag_aggregation_sums_ciphertext_components() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();
    let tag = test_tag(42);

    let first = encrypt(&parameters, &public_key, tag.clone(), 3).expect("must encrypt");
    let second = encrypt(&parameters, &public_key, tag.clone(), 4).expect("must encrypt");

    let aggregate =
        aggregate_same_tag(&parameters, &[first.clone(), second.clone()]).expect("must aggregate");

    assert_eq!(aggregate.parameter_id(), parameters.parameter_id());
    assert_eq!(aggregate.tag(), &tag);
    assert_eq!(aggregate.item_count(), 2);

    let expected_u = (first.u().into_group() + second.u().into_group()).into_affine();
    let expected_v = *first.v() * second.v();

    assert_eq!(aggregate.u(), expected_u);
    assert_eq!(*aggregate.v(), expected_v);
}

#[test]
fn same_tag_aggregation_rejects_an_empty_input() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");

    assert_eq!(
        aggregate_same_tag(&parameters, &[]),
        Err(HsweError::EmptyAggregate)
    );
}

#[test]
fn same_tag_aggregation_rejects_mixed_tags() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let first = encrypt(&parameters, &public_key, test_tag(42), 3).expect("must encrypt");
    let second = encrypt(&parameters, &public_key, test_tag(43), 4).expect("must encrypt");

    assert_eq!(
        aggregate_same_tag(&parameters, &[first, second]),
        Err(HsweError::IncompatibleTags)
    );
}

#[test]
fn same_tag_aggregation_rejects_parameter_mismatch() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let other_parameters = HsweParameters::new(11, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&other_parameters);
    let public_key = secret_key.public_key();

    let ciphertext =
        encrypt(&other_parameters, &public_key, test_tag(42), 3).expect("must encrypt");

    assert_eq!(
        aggregate_same_tag(&parameters, &[ciphertext]),
        Err(HsweError::IncompatibleParameters)
    );
}

#[test]
fn cross_tag_aggregate_decrypts_to_the_message_sum() {
    use hswe_implementation::{
        aggregation::aggregate_cross_tag, decryption::decrypt_cross_tag_aggregate,
        lookup::TargetLookupTable,
    };

    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let first_tag = test_tag(42);
    let second_tag = test_tag(43);
    let third_tag = test_tag(44);

    let ciphertexts = vec![
        encrypt(&parameters, &public_key, first_tag.clone(), 2).expect("must encrypt"),
        encrypt(&parameters, &public_key, second_tag.clone(), 3).expect("must encrypt"),
        encrypt(&parameters, &public_key, third_tag.clone(), 5).expect("must encrypt"),
    ];

    let aggregate = aggregate_cross_tag(&parameters, &ciphertexts).expect("must aggregate");

    let signatures = vec![
        secret_key.sign(&first_tag),
        secret_key.sign(&second_tag),
        secret_key.sign(&third_tag),
    ];

    let lookup_table =
        TargetLookupTable::new(parameters.parameter_id(), 10).expect("table must build");

    assert_eq!(
        decrypt_cross_tag_aggregate(
            &parameters,
            &public_key,
            &aggregate,
            &signatures,
            &lookup_table,
        ),
        Ok(10),
    );
}
