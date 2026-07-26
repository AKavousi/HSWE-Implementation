use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    pairing::Pairing,
};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use rand::rngs::OsRng;

use crate::{
    ciphertext::Ciphertext,
    error::{HsweError, Result},
    keys::{hash_tag, HswePublicKey},
    params::HsweParameters,
    tag::Tag,
};

/// Encrypts a bounded non-negative message under `tag` and `public_key`.
///
/// The ciphertext is `(U, V)`, where:
///
/// `U = g2^r`
///
/// `V = gT^message * e(H(tag), public_key)^r`
pub fn encrypt(
    parameters: &HsweParameters,
    public_key: &HswePublicKey,
    tag: Tag,
    message: u64,
) -> Result<Ciphertext> {
    if public_key.parameter_id() != parameters.parameter_id() {
        return Err(HsweError::IncompatibleParameters);
    }

    if public_key.point().is_zero() {
        return Err(HsweError::InvalidPublicKey);
    }

    if message > parameters.individual_message_max() {
        return Err(HsweError::MessageOutOfRange);
    }

    let mut rng = OsRng;
    let randomness = loop {
        let candidate = Fr::rand(&mut rng);
        if !candidate.is_zero() {
            break candidate;
        }
    };

    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();

    let message_generator = Bls12_381::pairing(g1, g2).0;
    let message_component = message_generator.pow([message]);

    let mask_base = Bls12_381::pairing(hash_tag(&tag), public_key.point()).0;
    let mask = mask_base.pow(randomness.into_bigint());

    let u = g2.mul_bigint(randomness.into_bigint()).into_affine();
    let v = message_component * mask;

    Ok(Ciphertext::new(parameters.parameter_id(), tag, u, v))
}
