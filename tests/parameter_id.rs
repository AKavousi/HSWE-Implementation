use hswe_implementation::{
    error::HsweError,
    params::{AGGREGATE_MESSAGE_MAX, HsweParameters, INDIVIDUAL_MESSAGE_MAX},
};

#[test]
fn default_parameters_use_expected_bounds() {
    let parameters = HsweParameters::v0_1().expect("v0.1 parameters must be valid");

    assert_eq!(parameters.individual_message_max(), INDIVIDUAL_MESSAGE_MAX);
    assert_eq!(parameters.aggregate_message_max(), AGGREGATE_MESSAGE_MAX);
}

#[test]
fn identical_parameters_have_identical_identifiers() {
    let first = HsweParameters::v0_1().expect("parameters must be valid");
    let second = HsweParameters::v0_1().expect("parameters must be valid");

    assert_eq!(first.parameter_id(), second.parameter_id());
}

#[test]
fn changing_a_bound_changes_the_identifier() {
    let default_parameters = HsweParameters::v0_1().expect("parameters must be valid");
    let changed_parameters = HsweParameters::new(100, 200).expect("parameters must be valid");

    assert_ne!(
        default_parameters.parameter_id(),
        changed_parameters.parameter_id()
    );
}

#[test]
fn individual_bound_cannot_exceed_aggregate_bound() {
    assert_eq!(
        HsweParameters::new(11, 10),
        Err(HsweError::UnsupportedParameters)
    );
}
