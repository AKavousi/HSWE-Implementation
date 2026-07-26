use sha2::{Digest, Sha256};

use crate::error::{HsweError, Result};

pub const HSWE_VERSION: u8 = 1;
pub const INDIVIDUAL_MESSAGE_MAX: u64 = 65_535;
pub const AGGREGATE_MESSAGE_MAX: u64 = 65_535;

/// A 32-byte identifier binding objects to one public HSWE configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParameterId([u8; 32]);

impl ParameterId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public, non-secret HSWE v0.1 configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HsweParameters {
    individual_message_max: u64,
    aggregate_message_max: u64,
    parameter_id: ParameterId,
}

impl HsweParameters {
    pub fn v0_1() -> Result<Self> {
        Self::new(INDIVIDUAL_MESSAGE_MAX, AGGREGATE_MESSAGE_MAX)
    }

    pub fn new(individual_message_max: u64, aggregate_message_max: u64) -> Result<Self> {
        if individual_message_max > aggregate_message_max {
            return Err(HsweError::UnsupportedParameters);
        }

        let parameter_id = Self::derive_parameter_id(individual_message_max, aggregate_message_max);

        Ok(Self {
            individual_message_max,
            aggregate_message_max,
            parameter_id,
        })
    }

    pub fn individual_message_max(&self) -> u64 {
        self.individual_message_max
    }

    pub fn aggregate_message_max(&self) -> u64 {
        self.aggregate_message_max
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    fn derive_parameter_id(individual_message_max: u64, aggregate_message_max: u64) -> ParameterId {
        let mut hasher = Sha256::new();

        hasher.update(b"HSWE");
        hasher.update([HSWE_VERSION]);
        hasher.update(b"BLS12-381");
        hasher.update(b"G1xG2->GT");
        hasher.update(b"HSWE-V01_BLS12381G1_XMD:SHA-256_SSWU_RO_");
        hasher.update(individual_message_max.to_be_bytes());
        hasher.update(aggregate_message_max.to_be_bytes());

        ParameterId(hasher.finalize().into())
    }
}
