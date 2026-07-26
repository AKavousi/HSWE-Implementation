use ark_bls12_381::Bls12_381;
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::One;

use hswe_implementation::{error::HsweError, lookup::TargetLookupTable, params::HsweParameters};

#[test]
fn lookup_recovers_every_value_in_its_configured_range() {
    let parameters = HsweParameters::new(4, 10).expect("parameters must be valid");
    let table = TargetLookupTable::new(parameters.parameter_id(), 10).expect("table must build");

    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();
    let generator = Bls12_381::pairing(g1, g2).0;
    let mut current = <Bls12_381 as Pairing>::TargetField::one();

    for message in 0..=10 {
        assert_eq!(table.lookup(&current), Ok(message));
        current *= generator;
    }
}

#[test]
fn lookup_rejects_a_value_outside_its_configured_range() {
    let parameters = HsweParameters::new(4, 10).expect("parameters must be valid");
    let table = TargetLookupTable::new(parameters.parameter_id(), 2).expect("table must build");

    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();
    let generator = Bls12_381::pairing(g1, g2).0;

    let out_of_range = generator * generator * generator;

    assert_eq!(
        table.lookup(&out_of_range),
        Err(HsweError::DiscreteLogOutOfRange)
    );
}

#[test]
fn lookup_records_its_bound_parameter_identifier() {
    let parameters = HsweParameters::new(4, 10).expect("parameters must be valid");
    let table = TargetLookupTable::new(parameters.parameter_id(), 10).expect("table must build");

    assert_eq!(table.parameter_id(), parameters.parameter_id());
    assert_eq!(table.maximum_message(), 10);
}
