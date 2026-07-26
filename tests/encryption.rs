use ark_bls12_381::Bls12_381;
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::Field;

use hswe_implementation::{
    encryption::encrypt, error::HsweError, keys::HsweSecretKey, params::HsweParameters, tag::Tag,
};

fn test_tag() -> Tag {
    Tag::epoch("test-domain", 42).expect("test tag must be valid")
}

#[test]
fn encryption_binds_ciphertext_to_parameters_and_tag() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();
    let tag = test_tag();

    let ciphertext =
        encrypt(&parameters, &public_key, tag.clone(), 7).expect("encryption must succeed");

    assert_eq!(ciphertext.parameter_id(), parameters.parameter_id());
    assert_eq!(ciphertext.tag(), &tag);
}

#[test]
fn valid_signature_cancels_encryption_mask() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();
    let tag = test_tag();
    let message = 7;

    let ciphertext =
        encrypt(&parameters, &public_key, tag.clone(), message).expect("encryption must succeed");
    let signature = secret_key.sign(&tag);

    let pairing_mask = Bls12_381::pairing(signature.point(), ciphertext.u()).0;
    let recovered_target = *ciphertext.v()
        * pairing_mask
            .inverse()
            .expect("pairing of non-zero points must be invertible");

    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();
    let message_generator = Bls12_381::pairing(g1, g2).0;

    assert_eq!(recovered_target, message_generator.pow([message]));
}

#[test]
fn encryption_rejects_messages_above_individual_limit() {
    let parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    assert_eq!(
        encrypt(&parameters, &public_key, test_tag(), 11),
        Err(HsweError::MessageOutOfRange)
    );
}

#[test]
fn encryption_rejects_public_key_from_different_parameters() {
    let encryption_parameters = HsweParameters::new(10, 100).expect("parameters must be valid");
    let key_parameters = HsweParameters::new(11, 100).expect("parameters must be valid");
    let secret_key = HsweSecretKey::generate(&key_parameters);
    let public_key = secret_key.public_key();

    assert_eq!(
        encrypt(&encryption_parameters, &public_key, test_tag(), 7),
        Err(HsweError::IncompatibleParameters)
    );
}
