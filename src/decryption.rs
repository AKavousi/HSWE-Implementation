use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::Field;

use crate::{
    ciphertext::{Ciphertext, SameTagAggregate, TagSignature},
    error::{HsweError, Result},
    keys::HswePublicKey,
    lookup::TargetLookupTable,
    params::HsweParameters,
};

/// Decrypts one ciphertext using a valid signature for its embedded tag.
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
pub fn decrypt_same_tag_aggregate(
    parameters: &HsweParameters,
    public_key: &HswePublicKey,
    aggregate: &SameTagAggregate,
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
