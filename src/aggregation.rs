use ark_bls12_381::{Bls12_381, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::{One, Zero};

use crate::{
    ciphertext::{Ciphertext, SameTagAggregate},
    error::{HsweError, Result},
    params::HsweParameters,
};

/// Homomorphically aggregates ciphertexts encrypted under the same tag.
///
/// The returned aggregate encrypts the sum of the input messages.
pub fn aggregate_same_tag(
    parameters: &HsweParameters,
    ciphertexts: &[Ciphertext],
) -> Result<SameTagAggregate> {
    let first = ciphertexts.first().ok_or(HsweError::EmptyAggregate)?;

    if first.parameter_id() != parameters.parameter_id() {
        return Err(HsweError::IncompatibleParameters);
    }

    let tag = first.tag().clone();
    let mut u = G2Projective::zero();
    let mut v = <Bls12_381 as ark_ec::pairing::Pairing>::TargetField::one();
    let mut item_count = 0u64;

    for ciphertext in ciphertexts {
        if ciphertext.parameter_id() != parameters.parameter_id() {
            return Err(HsweError::IncompatibleParameters);
        }

        if ciphertext.tag() != &tag {
            return Err(HsweError::IncompatibleTags);
        }

        item_count = item_count
            .checked_add(1)
            .ok_or(HsweError::ItemCountOverflow)?;

        u += ciphertext.u();
        v *= ciphertext.v();
    }

    Ok(SameTagAggregate::new(
        parameters.parameter_id(),
        tag,
        item_count,
        u.into_affine(),
        v,
    ))
}
