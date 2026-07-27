use ark_bls12_381::{Bls12_381, Fr, G1Projective, g1};
use ark_ec::{
    PrimeGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
};
use ark_ff::{Field, PrimeField, UniformRand, Zero, field_hashers::DefaultFieldHasher};
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::ciphertext::{Ciphertext, SameTagAggregate};

const PRIVACY_GENERATOR_DST: &[u8] = b"HSWE-V01_PRIVACY_GENERATOR_BLS12381G1_XMD:SHA-256_SSWU_RO_";

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

/// Samples a fresh non-zero scalar for one user's ciphertext blind.
pub fn sample_blind() -> Fr {
    let mut rng = OsRng;

    loop {
        let candidate = Fr::rand(&mut rng);

        if !candidate.is_zero() {
            return candidate;
        }
    }
}

/// Returns a fixed, domain-separated target-group element used only for
/// privacy blinding.
pub fn privacy_generator() -> <Bls12_381 as Pairing>::TargetField {
    let hasher = G1Hasher::new(PRIVACY_GENERATOR_DST).expect("fixed privacy DST is valid");

    let h_g1 = hasher
        .hash(b"HSWE privacy blinding generator")
        .expect("fixed privacy generator hash must succeed");

    let g2 = <Bls12_381 as Pairing>::G2::generator();

    Bls12_381::pairing(h_g1, g2).0
}

/// Blinds an individual ciphertext without changing its tag or U component.
pub fn blind_ciphertext(ciphertext: &Ciphertext, blind: Fr) -> Ciphertext {
    let h_to_blind = privacy_generator().pow(blind.into_bigint());
    let blinded_v = *ciphertext.v() * h_to_blind;

    Ciphertext::new(
        ciphertext.parameter_id(),
        ciphertext.tag().clone(),
        ciphertext.u(),
        blinded_v,
    )
}

/// Removes the aggregate blind before standard same-tag decryption.
pub fn remove_aggregate_blind(
    aggregate: &SameTagAggregate,
    aggregate_blind: Fr,
) -> SameTagAggregate {
    let h_to_sum = privacy_generator().pow(aggregate_blind.into_bigint());

    let inverse = h_to_sum
        .inverse()
        .expect("a non-zero target-group element has an inverse");

    SameTagAggregate::new(
        aggregate.parameter_id(),
        aggregate.tag().clone(),
        aggregate.item_count(),
        aggregate.u(),
        *aggregate.v() * inverse,
    )
}
