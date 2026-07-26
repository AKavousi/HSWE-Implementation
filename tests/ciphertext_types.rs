use ark_bls12_381::Bls12_381;
use ark_ec::{CurveGroup, PrimeGroup, pairing::Pairing};
use hswe_implementation::{
    ciphertext::{Ciphertext, CrossTagAggregate, SameTagAggregate, TaggedU},
    params::HsweParameters,
    tag::Tag,
};

#[test]
fn ciphertext_and_aggregate_containers_preserve_metadata() {
    let parameters = HsweParameters::v0_1().expect("parameters must be valid");
    let parameter_id = parameters.parameter_id();
    let tag = Tag::epoch("hswe.example", 42).expect("tag must be valid");

    let u = <Bls12_381 as Pairing>::G2::generator().into_affine();
    let v = Bls12_381::pairing(
        <Bls12_381 as Pairing>::G1::generator(),
        <Bls12_381 as Pairing>::G2::generator(),
    )
    .0;

    let ciphertext = Ciphertext::new(parameter_id, tag.clone(), u, v);
    assert_eq!(ciphertext.parameter_id(), parameter_id);
    assert_eq!(ciphertext.tag(), &tag);

    let same_tag = SameTagAggregate::new(parameter_id, tag.clone(), 3, u, v);
    assert_eq!(same_tag.item_count(), 3);
    assert_eq!(same_tag.tag(), &tag);

    let cross_tag = CrossTagAggregate::new(
        parameter_id,
        2,
        vec![
            TaggedU::new(tag.clone(), u),
            TaggedU::new(Tag::epoch("hswe.example", 43).unwrap(), u),
        ],
        v,
    );
    assert_eq!(cross_tag.item_count(), 2);
    assert_eq!(cross_tag.tagged_u().len(), 2);
}
