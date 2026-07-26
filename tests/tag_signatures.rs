use hswe_implementation::{keys::HsweSecretKey, params::HsweParameters, tag::Tag};

#[test]
fn valid_tag_signature_verifies() {
    let parameters = HsweParameters::v0_1().expect("default parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();
    let tag = Tag::epoch("auction.example", 42).expect("tag must be valid");

    let signature = secret_key.sign(&tag);

    assert_eq!(secret_key.parameter_id(), parameters.parameter_id());
    assert_eq!(public_key.parameter_id(), parameters.parameter_id());
    assert_eq!(signature.parameter_id(), parameters.parameter_id());
    assert!(public_key.verify(&tag, &signature));
}

#[test]
fn signature_does_not_verify_for_a_different_tag() {
    let parameters = HsweParameters::v0_1().expect("default parameters must be valid");
    let secret_key = HsweSecretKey::generate(&parameters);
    let public_key = secret_key.public_key();

    let signed_tag = Tag::epoch("auction.example", 42).expect("tag must be valid");
    let other_tag = Tag::epoch("auction.example", 43).expect("tag must be valid");

    let signature = secret_key.sign(&signed_tag);

    assert!(!public_key.verify(&other_tag, &signature));
}

#[test]
fn signature_does_not_verify_under_a_different_public_key() {
    let parameters = HsweParameters::v0_1().expect("default parameters must be valid");
    let signer = HsweSecretKey::generate(&parameters);
    let other_signer = HsweSecretKey::generate(&parameters);
    let tag = Tag::epoch("auction.example", 42).expect("tag must be valid");

    let signature = signer.sign(&tag);

    assert!(signer.public_key().verify(&tag, &signature));
    assert!(!other_signer.public_key().verify(&tag, &signature));
}

#[test]
fn signature_is_rejected_when_parameter_ids_differ() {
    let signer_parameters = HsweParameters::new(10, 20).expect("custom parameters must be valid");
    let verifier_parameters = HsweParameters::new(11, 20).expect("custom parameters must be valid");

    let signer = HsweSecretKey::generate(&signer_parameters);
    let verifier = HsweSecretKey::generate(&verifier_parameters);
    let tag = Tag::epoch("auction.example", 42).expect("tag must be valid");

    let signature = signer.sign(&tag);

    assert_ne!(
        signer_parameters.parameter_id(),
        verifier_parameters.parameter_id()
    );
    assert!(!verifier.public_key().verify(&tag, &signature));
}
