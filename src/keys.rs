use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, g1};
use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
};
use ark_ff::{PrimeField, UniformRand, Zero, field_hashers::DefaultFieldHasher};
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::{
    ciphertext::TagSignature,
    params::{HsweParameters, ParameterId},
    tag::Tag,
};

const HSWE_TAG_DST: &[u8] = b"HSWE-V01_BLS12381G1_XMD:SHA-256_SSWU_RO_";

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

fn hash_tag(tag: &Tag) -> G1Affine {
    let hasher =
        G1Hasher::new(HSWE_TAG_DST).expect("the fixed HSWE hash-to-curve configuration is valid");

    hasher
        .hash(&tag.to_canonical_bytes())
        .expect("hashing a canonical HSWE tag must succeed")
}

/// A secret BLS signing scalar bound to one HSWE parameter configuration.
///
/// This type intentionally does not implement `Clone`, `Copy`, or `Debug`.
pub struct HsweSecretKey {
    parameter_id: ParameterId,
    scalar: Fr,
}

impl HsweSecretKey {
    /// Samples a fresh non-zero BLS secret scalar using the operating-system RNG.
    pub fn generate(parameters: &HsweParameters) -> Self {
        let mut rng = OsRng;
        let scalar = loop {
            let candidate = Fr::rand(&mut rng);
            if !candidate.is_zero() {
                break candidate;
            }
        };

        Self {
            parameter_id: parameters.parameter_id(),
            scalar,
        }
    }

    /// Returns the parameter configuration bound to this key.
    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    /// Derives the corresponding public verification key.
    pub fn public_key(&self) -> HswePublicKey {
        let point = <Bls12_381 as Pairing>::G2::generator()
            .mul_bigint(self.scalar.into_bigint())
            .into_affine();

        HswePublicKey {
            parameter_id: self.parameter_id,
            point,
        }
    }

    /// Produces a BLS signature over a canonical HSWE tag.
    pub fn sign(&self, tag: &Tag) -> TagSignature {
        let point = hash_tag(tag)
            .mul_bigint(self.scalar.into_bigint())
            .into_affine();

        TagSignature::new(self.parameter_id, point)
    }
}

/// A public BLS verification key bound to one HSWE parameter configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HswePublicKey {
    parameter_id: ParameterId,
    point: G2Affine,
}

impl HswePublicKey {
    /// Returns the parameter configuration bound to this key.
    pub fn parameter_id(&self) -> ParameterId {
        self.parameter_id
    }

    /// Returns the public point \(sG_2\).
    pub fn point(&self) -> G2Affine {
        self.point
    }

    /// Verifies a signature over a canonical HSWE tag.
    pub fn verify(&self, tag: &Tag, signature: &TagSignature) -> bool {
        if self.parameter_id != signature.parameter_id() {
            return false;
        }

        if self.point.is_zero() || signature.point().is_zero() {
            return false;
        }

        let g2 = <Bls12_381 as Pairing>::G2::generator();

        Bls12_381::pairing(signature.point(), g2) == Bls12_381::pairing(hash_tag(tag), self.point)
    }
}
