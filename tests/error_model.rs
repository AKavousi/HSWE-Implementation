use hswe_implementation::error::HsweError;

#[test]
fn errors_have_stable_human_readable_messages() {
    assert_eq!(
        HsweError::IncompatibleTags.to_string(),
        "ciphertexts or aggregates use different tags"
    );

    assert_eq!(
        HsweError::DiscreteLogOutOfRange.to_string(),
        "target-group value is outside the discrete-log lookup range"
    );
}
