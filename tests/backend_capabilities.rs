use ark_bls12_381::{Bls12_381, Fr, G1Projective, g1};
use ark_ec::{
    PrimeGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
};
use ark_ff::{PrimeField, Zero, field_hashers::DefaultFieldHasher};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

const HSWE_TAG_DST: &[u8] = b"HSWE-V01_BLS12381G1_XMD:SHA-256_SSWU_RO_";

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

#[test]
fn pairing_is_nondegenerate_bilinear_and_serializable() {
    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();

    let pairing = Bls12_381::pairing(g1, g2);
    assert!(!pairing.is_zero());

    let a = Fr::from(5_u64);
    let b = Fr::from(7_u64);

    let scaled_g1 = g1.mul_bigint(a.into_bigint());
    let scaled_g2 = g2.mul_bigint(b.into_bigint());

    let left = Bls12_381::pairing(scaled_g1, scaled_g2);
    let right = pairing.mul_bigint((a * b).into_bigint());

    assert_eq!(left, right);

    let mut bytes = Vec::new();
    pairing
        .serialize_compressed(&mut bytes)
        .expect("pairing output must serialize");

    let recovered =
        <ark_ec::pairing::PairingOutput<Bls12_381>>::deserialize_compressed(bytes.as_slice())
            .expect("pairing output must deserialize");

    assert_eq!(pairing, recovered);
}

#[test]
fn truncated_pairing_output_is_rejected() {
    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();
    let pairing = Bls12_381::pairing(g1, g2);

    let mut bytes = Vec::new();
    pairing
        .serialize_compressed(&mut bytes)
        .expect("pairing output must serialize");

    bytes.pop();

    let recovered =
        <ark_ec::pairing::PairingOutput<Bls12_381>>::deserialize_compressed(bytes.as_slice());

    assert!(recovered.is_err());
}

#[test]
fn hash_to_g1_is_deterministic_domain_separated_and_serializable() {
    let tag = b"hswe.example/epoch/2026-07-26";

    let hasher = G1Hasher::new(HSWE_TAG_DST).expect("HSWE hasher must initialize");
    let same_tag_hash = hasher.hash(tag).expect("tag hashing must succeed");
    let repeated_hash = hasher.hash(tag).expect("tag hashing must succeed");

    assert_eq!(same_tag_hash, repeated_hash);

    let changed_tag_hash = hasher
        .hash(b"hswe.example/epoch/2026-07-27")
        .expect("tag hashing must succeed");
    assert_ne!(same_tag_hash, changed_tag_hash);

    let other_domain_hasher = G1Hasher::new(b"HSWE-V01_TEST_OTHER_DOMAIN")
        .expect("alternate-domain hasher must initialize");
    let other_domain_hash = other_domain_hasher
        .hash(tag)
        .expect("tag hashing must succeed");
    assert_ne!(same_tag_hash, other_domain_hash);

    let mut bytes = Vec::new();
    same_tag_hash
        .serialize_compressed(&mut bytes)
        .expect("G1 hash output must serialize");

    let recovered = <ark_bls12_381::G1Affine>::deserialize_compressed(bytes.as_slice())
        .expect("G1 hash output must deserialize");

    assert_eq!(same_tag_hash, recovered);
}

#[test]
fn report_canonical_serialized_sizes() {
    let g1 = <Bls12_381 as Pairing>::G1::generator();
    let g2 = <Bls12_381 as Pairing>::G2::generator();
    let gt = Bls12_381::pairing(g1, g2);

    let mut g1_bytes = Vec::new();
    let mut g2_bytes = Vec::new();
    let mut gt_bytes = Vec::new();

    g1.serialize_compressed(&mut g1_bytes)
        .expect("G1 generator must serialize");
    g2.serialize_compressed(&mut g2_bytes)
        .expect("G2 generator must serialize");
    gt.serialize_compressed(&mut gt_bytes)
        .expect("GT pairing result must serialize");

    println!(
        "canonical compressed sizes: G1={} bytes, G2={} bytes, GT={} bytes",
        g1_bytes.len(),
        g2_bytes.len(),
        gt_bytes.len()
    );

    assert!(!g1_bytes.is_empty());
    assert!(!g2_bytes.is_empty());
    assert!(!gt_bytes.is_empty());
}
