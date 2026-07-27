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

/// Homomorphically aggregates ciphertexts encrypted under potentially
/// different tags but under one parameter configuration.
///
/// Each tag and its corresponding `U` component are retained so that the
/// aggregate can later be decrypted with the matching tag signatures.
pub fn aggregate_cross_tag(
    parameters: &HsweParameters,
    ciphertexts: &[Ciphertext],
) -> Result<crate::ciphertext::CrossTagAggregate> {
    if ciphertexts.is_empty() {
        return Err(HsweError::EmptyAggregate);
    }

    let mut tagged_u = Vec::with_capacity(ciphertexts.len());
    let mut v = <Bls12_381 as ark_ec::pairing::Pairing>::TargetField::one();
    let mut item_count = 0u64;

    for ciphertext in ciphertexts {
        if ciphertext.parameter_id() != parameters.parameter_id() {
            return Err(HsweError::IncompatibleParameters);
        }

        item_count = item_count
            .checked_add(1)
            .ok_or(HsweError::ItemCountOverflow)?;

        tagged_u.push(crate::ciphertext::TaggedU::new(
            ciphertext.tag().clone(),
            ciphertext.u(),
        ));
        v *= ciphertext.v();
    }

    Ok(crate::ciphertext::CrossTagAggregate::new(
        parameters.parameter_id(),
        item_count,
        tagged_u,
        v,
    ))
}
