use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One};

use crate::{
    ciphertext::{Ciphertext, TagSignature},
    error::{HsweError, Result},
    keys::HswePublicKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
};

/// Decrypts one ciphertext using a valid signature for its embedded tag.
///
/// The signature acts as the witness/decryption key. The lookup table must
/// have been built for the same parameter configuration.
pub fn decrypt(
    parameters: &HsweParameters,
    public_key: &HswePublicKey,
    ciphertext: &Ciphertext,
    signature: &TagSignature,
    lookup_table: &TargetLookupTable,
) -> Result<u64> {
    if ciphertext.parameter_id() != parameters.parameter_id()
        || public_key.parameter_id() != parameters.parameter_id()
        || signature.parameter_id() != parameters.parameter_id()
    {
        return Err(HsweError::IncompatibleParameters);
    }

    if lookup_table.parameter_id() != parameters.parameter_id() {
        return Err(HsweError::LookupTableMismatch);
    }

    if !public_key.verify(ciphertext.tag(), signature) {
        return Err(HsweError::InvalidSignature);
    }

    let mask = Bls12_381::pairing(signature.point(), ciphertext.u()).0;
    let inverse_mask = mask.inverse().ok_or(HsweError::InvalidCiphertext)?;
    let recovered_target = *ciphertext.v() * inverse_mask;

    lookup_table.lookup(&recovered_target)
}

/// Decrypts a same-tag aggregate using one tag signature.
///
/// The result is the sum of all messages represented by the aggregate.
pub fn decrypt_same_tag_aggregate(
    parameters: &HsweParameters,
    public_key: &HswePublicKey,
    aggregate: &crate::ciphertext::SameTagAggregate,
    signature: &TagSignature,
    lookup_table: &TargetLookupTable,
) -> Result<u64> {
    if aggregate.parameter_id() != parameters.parameter_id()
        || public_key.parameter_id() != parameters.parameter_id()
        || signature.parameter_id() != parameters.parameter_id()
    {
        return Err(HsweError::IncompatibleParameters);
    }

    if lookup_table.parameter_id() != parameters.parameter_id() {
        return Err(HsweError::LookupTableMismatch);
    }

    if !public_key.verify(aggregate.tag(), signature) {
        return Err(HsweError::InvalidSignature);
    }

    let mask = Bls12_381::pairing(signature.point(), aggregate.u()).0;
    let inverse_mask = mask.inverse().ok_or(HsweError::InvalidAggregate)?;
    let recovered_target = *aggregate.v() * inverse_mask;

    lookup_table.lookup(&recovered_target)
}

/// Decrypts a cross-tag aggregate.
///
/// `signatures` must be supplied in precisely the same order as the aggregate's
/// retained `(tag, U)` entries.
pub fn decrypt_cross_tag_aggregate(
    parameters: &HsweParameters,
    public_key: &HswePublicKey,
    aggregate: &crate::ciphertext::CrossTagAggregate,
    signatures: &[TagSignature],
    lookup_table: &TargetLookupTable,
) -> Result<u64> {
    if aggregate.parameter_id() != parameters.parameter_id()
        || public_key.parameter_id() != parameters.parameter_id()
    {
        return Err(HsweError::IncompatibleParameters);
    }

    if lookup_table.parameter_id() != parameters.parameter_id() {
        return Err(HsweError::LookupTableMismatch);
    }

    if signatures.len() != aggregate.tagged_u().len() {
        return Err(HsweError::InvalidSignature);
    }

    let mut masks = <Bls12_381 as Pairing>::TargetField::one();

    for (tagged_u, signature) in aggregate.tagged_u().iter().zip(signatures) {
        if signature.parameter_id() != parameters.parameter_id() {
            return Err(HsweError::IncompatibleParameters);
        }

        if !public_key.verify(tagged_u.tag(), signature) {
            return Err(HsweError::InvalidSignature);
        }

        masks *= Bls12_381::pairing(signature.point(), tagged_u.u()).0;
    }

    let inverse_masks = masks.inverse().ok_or(HsweError::InvalidAggregate)?;
    let recovered_target = *aggregate.v() * inverse_masks;

    lookup_table.lookup(&recovered_target)
}
