use std::collections::HashMap;

use ark_bls12_381::Bls12_381;
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::One;
use ark_serialize::CanonicalSerialize;

use crate::{
    error::{HsweError, Result},
    params::ParameterId,
};

/// A precomputed bounded discrete-log table for the fixed generator in GT.
///
/// It maps canonical compressed encodings of \(g_T^m\) to non-negative
/// messages `m` in `0..=maximum_message`.
#[derive(Clone, Debug)]
pub struct TargetLookupTable {
    parameter_id: ParameterId,
    maximum_message: u64,
    entries: HashMap<Vec<u8>, u64>,
}

impl TargetLookupTable {
    /// Precomputes all target-group powers for `0..=maximum_message`.
    pub fn new(parameter_id: ParameterId, maximum_message: u64) -> Result<Self> {
        let capacity = usize::try_from(
            maximum_message
                .checked_add(1)
                .ok_or(HsweError::ResourceLimitExceeded)?,
        )
        .map_err(|_| HsweError::ResourceLimitExceeded)?;

        let g1 = <Bls12_381 as Pairing>::G1::generator();
        let g2 = <Bls12_381 as Pairing>::G2::generator();
        let generator = Bls12_381::pairing(g1, g2).0;

        let mut entries = HashMap::with_capacity(capacity);
        let mut current = <Bls12_381 as Pairing>::TargetField::one();

        for message in 0..=maximum_message {
            let mut encoded = Vec::new();
            current
                .serialize_compressed(&mut encoded)
                .map_err(|_| HsweError::MalformedSerialization)?;

            entries.insert(encoded, message);
            current *= generator;
        }

        Ok(Self {
            parameter_id,
            maximum_message,
            entries,
        })
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    pub fn maximum_message(&self) -> u64 {
        self.maximum_message
    }

    pub fn lookup(&self, value: &<Bls12_381 as Pairing>::TargetField) -> Result<u64> {
        let mut encoded = Vec::new();
        value
            .serialize_compressed(&mut encoded)
            .map_err(|_| HsweError::MalformedSerialization)?;

        self.entries
            .get(&encoded)
            .copied()
            .ok_or(HsweError::DiscreteLogOutOfRange)
    }
}
