use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;

use crate::{params::ParameterId, tag::Tag};

/// A BLS signature on a canonical HSWE tag.
///
/// The signing and verification operations are added in M3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagSignature {
    parameter_id: ParameterId,
    point: G1Affine,
}

impl TagSignature {
    pub fn new(parameter_id: ParameterId, point: G1Affine) -> Self {
        Self {
            parameter_id,
            point,
        }
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    pub fn point(&self) -> G1Affine {
        self.point
    }
}

/// A pairing-based HSWE ciphertext encrypted under one canonical tag.
///
/// `u` is in G2 and `v` is in GT. Encryption is added in M3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    parameter_id: ParameterId,
    tag: Tag,
    u: G2Affine,
    v: <Bls12_381 as Pairing>::TargetField,
}

impl Ciphertext {
    pub fn new(
        parameter_id: ParameterId,
        tag: Tag,
        u: G2Affine,
        v: <Bls12_381 as Pairing>::TargetField,
    ) -> Self {
        Self {
            parameter_id,
            tag,
            u,
            v,
        }
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    pub fn u(&self) -> G2Affine {
        self.u
    }

    pub fn v(&self) -> &<Bls12_381 as Pairing>::TargetField {
        &self.v
    }
}

/// A same-tag aggregate.
///
/// Aggregation and decryption are added in later milestones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SameTagAggregate {
    parameter_id: ParameterId,
    tag: Tag,
    item_count: u64,
    u: G2Affine,
    v: <Bls12_381 as Pairing>::TargetField,
}

impl SameTagAggregate {
    pub fn new(
        parameter_id: ParameterId,
        tag: Tag,
        item_count: u64,
        u: G2Affine,
        v: <Bls12_381 as Pairing>::TargetField,
    ) -> Self {
        Self {
            parameter_id,
            tag,
            item_count,
            u,
            v,
        }
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    pub fn item_count(&self) -> u64 {
        self.item_count
    }

    pub fn u(&self) -> G2Affine {
        self.u
    }

    pub fn v(&self) -> &<Bls12_381 as Pairing>::TargetField {
        &self.v
    }
}

/// One source-group component and its tag, retained for cross-tag decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedU {
    tag: Tag,
    u: G2Affine,
}

impl TaggedU {
    pub fn new(tag: Tag, u: G2Affine) -> Self {
        Self { tag, u }
    }

    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    pub fn u(&self) -> G2Affine {
        self.u
    }
}

/// An aggregate across different tags under one parameter configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossTagAggregate {
    parameter_id: ParameterId,
    item_count: u64,
    tagged_u: Vec<TaggedU>,
    v: <Bls12_381 as Pairing>::TargetField,
}

impl CrossTagAggregate {
    pub fn new(
        parameter_id: ParameterId,
        item_count: u64,
        tagged_u: Vec<TaggedU>,
        v: <Bls12_381 as Pairing>::TargetField,
    ) -> Self {
        Self {
            parameter_id,
            item_count,
            tagged_u,
            v,
        }
    }

    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    pub fn item_count(&self) -> u64 {
        self.item_count
    }

    pub fn tagged_u(&self) -> &[TaggedU] {
        &self.tagged_u
    }

    pub fn v(&self) -> &<Bls12_381 as Pairing>::TargetField {
        &self.v
    }
}
