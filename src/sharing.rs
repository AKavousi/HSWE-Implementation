use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand, Zero};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScalarShare {
    index: u64,
    value: Fr,
}

impl ScalarShare {
    pub fn new(index: u64, value: Fr) -> Result<Self, SharingError> {
        if index == 0 {
            return Err(SharingError::ZeroIndex);
        }

        Ok(Self { index, value })
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn value(&self) -> Fr {
        self.value
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SharingError {
    #[error("threshold must be at least one")]
    ZeroThreshold,

    #[error("threshold cannot exceed the number of shares")]
    ThresholdExceedsShareCount,

    #[error("share index must be non-zero")]
    ZeroIndex,

    #[error("not enough shares to reconstruct")]
    InsufficientShares,

    #[error("duplicate share index")]
    DuplicateShareIndex,

    #[error("failed to invert a field element")]
    NonInvertibleDenominator,
}

pub fn split_secret(
    secret: Fr,
    threshold: usize,
    share_count: usize,
) -> Result<Vec<ScalarShare>, SharingError> {
    if threshold == 0 {
        return Err(SharingError::ZeroThreshold);
    }

    if threshold > share_count {
        return Err(SharingError::ThresholdExceedsShareCount);
    }

    let mut rng = OsRng;
    let mut coefficients = Vec::with_capacity(threshold);
    coefficients.push(secret);

    for _ in 1..threshold {
        coefficients.push(Fr::rand(&mut rng));
    }

    let mut shares = Vec::with_capacity(share_count);

    for index in 1..=share_count {
        let x = Fr::from(index as u64);
        let mut value = Fr::zero();

        for coefficient in coefficients.iter().rev() {
            value *= x;
            value += coefficient;
        }

        shares.push(ScalarShare::new(index as u64, value)?);
    }

    Ok(shares)
}

pub fn reconstruct_secret(shares: &[ScalarShare], threshold: usize) -> Result<Fr, SharingError> {
    if threshold == 0 {
        return Err(SharingError::ZeroThreshold);
    }

    if shares.len() < threshold {
        return Err(SharingError::InsufficientShares);
    }

    let selected = &shares[..threshold];

    for (i, left) in selected.iter().enumerate() {
        for right in selected.iter().skip(i + 1) {
            if left.index() == right.index() {
                return Err(SharingError::DuplicateShareIndex);
            }
        }
    }

    let mut secret = Fr::zero();

    for (i, share_i) in selected.iter().enumerate() {
        let x_i = Fr::from(share_i.index());
        let mut lagrange_at_zero = Fr::from(1u64);

        for (j, share_j) in selected.iter().enumerate() {
            if i == j {
                continue;
            }

            let x_j = Fr::from(share_j.index());
            let denominator = x_j - x_i;

            let inverse = denominator
                .inverse()
                .ok_or(SharingError::NonInvertibleDenominator)?;

            lagrange_at_zero *= x_j * inverse;
        }

        secret += share_i.value() * lagrange_at_zero;
    }

    Ok(secret)
}
