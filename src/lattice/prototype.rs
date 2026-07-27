//! Insecure LWE-HSWE arithmetic research prototype.
//!
//! SECURITY WARNING: This code demonstrates ciphertext algebra and API shape.
//! It does not implement GPV trapdoors or secure discrete-Gaussian sampling.

use super::math::{add_vec_mod_q, centered_mod_q, dot_product_mod_q, mod_q};

pub const Q: i64 = 12_289;
pub const DIMENSION: usize = 16;
const MESSAGE_OFFSET: i64 = Q / 2;

/// Absolute decoding boundary for the binary `q/2` embedding.
pub const DECODE_BOUND: i64 = Q / 4;

/// Errors returned by the research-prototype API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrototypeError {
    EmptyAggregation,
    InvalidCiphertextDimension,
    MixedTags,
    TagMismatch,
}

impl core::fmt::Display for PrototypeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyAggregation => {
                write!(formatter, "cannot aggregate an empty ciphertext list")
            }
            Self::InvalidCiphertextDimension => {
                write!(formatter, "ciphertext has an invalid u dimension")
            }
            Self::MixedTags => write!(
                formatter,
                "cannot aggregate ciphertexts from different tags"
            ),
            Self::TagMismatch => write!(formatter, "witness does not match the ciphertext tag"),
        }
    }
}

impl std::error::Error for PrototypeError {}

/// A test-only ciphertext of the form `(tag_id, u, v)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToyCiphertext {
    /// API-level tag binding; not a cryptographic authentication tag.
    pub tag_id: u64,
    pub u: Vec<i64>,
    pub v: i64,
}

/// Returns whether a centered aggregate error is safely decodable.
pub fn is_within_noise_budget(centered_error: i64) -> bool {
    centered_error.abs() < DECODE_BOUND
}

/// Returns a deterministic identifier used for API-level tag binding.
///
/// This is not a cryptographic hash and must not be used in production.
pub fn tag_id(tag: &[u8]) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325_u64;

    for &byte in tag {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }

    state
}

/// Maps a tag deterministically to a small vector in `{-1, 0, 1}^DIMENSION`.
///
/// In a complete GPV implementation, this would be the public target
/// `y = H(tag)`, and extraction would sample a short secret preimage `x`
/// such that `A * x = y mod q`.
pub fn target_from_tag(tag: &[u8]) -> Vec<i64> {
    let state = tag_id(tag);

    (0..DIMENSION)
        .map(|index| {
            let mixed = state
                .wrapping_add((index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
                .rotate_left((index % 31) as u32);

            match mixed % 3 {
                0 => -1,
                1 => 0,
                _ => 1,
            }
        })
        .collect()
}

/// Returns the prototype witness for `tag`.
///
/// This deliberately uses `A = I`, so the witness equals the public target.
/// It is insecure and exists only to demonstrate the algebra.
pub fn extract_test_witness(tag: &[u8]) -> Vec<i64> {
    target_from_tag(tag)
}

/// Encrypts a binary message under `tag`.
///
/// This models the paper's LWE algebra with `A = I`:
/// `u = s + e1` and `v = <y, s> + e2 + b*q/2 mod q`.
pub fn encrypt_bit(bit: bool, tag: &[u8], nonce: u64) -> ToyCiphertext {
    let target = target_from_tag(tag);
    let secret = sample_small_vector(nonce.wrapping_mul(2).wrapping_add(1));
    let error_1 = sample_small_vector(nonce.wrapping_mul(2).wrapping_add(2));
    let error_2 = sample_small_scalar(nonce.wrapping_mul(2).wrapping_add(3));

    let u = add_vec_mod_q(&secret, &error_1, Q);
    let message = if bit { MESSAGE_OFFSET } else { 0 };

    let v = mod_q(
        dot_product_mod_q(&target, &secret, Q) + error_2 + message,
        Q,
    );

    ToyCiphertext {
        tag_id: tag_id(tag),
        u,
        v,
    }
}

/// Homomorphically aggregates same-tag ciphertexts by component-wise addition.
///
/// Returns an error if the input is empty, malformed, or contains mixed tags.
pub fn aggregate(ciphertexts: &[ToyCiphertext]) -> Result<ToyCiphertext, PrototypeError> {
    let first = ciphertexts
        .first()
        .ok_or(PrototypeError::EmptyAggregation)?;

    if first.u.len() != DIMENSION {
        return Err(PrototypeError::InvalidCiphertextDimension);
    }

    let expected_tag_id = first.tag_id;
    let mut aggregate_u = vec![0; DIMENSION];
    let mut aggregate_v = 0;

    for ciphertext in ciphertexts {
        if ciphertext.tag_id != expected_tag_id {
            return Err(PrototypeError::MixedTags);
        }

        if ciphertext.u.len() != DIMENSION {
            return Err(PrototypeError::InvalidCiphertextDimension);
        }

        aggregate_u = add_vec_mod_q(&aggregate_u, &ciphertext.u, Q);
        aggregate_v = mod_q(aggregate_v + ciphertext.v, Q);
    }

    Ok(ToyCiphertext {
        tag_id: expected_tag_id,
        u: aggregate_u,
        v: aggregate_v,
    })
}

/// Returns the centered phase before bit decoding.
pub fn decryption_phase(ciphertext: &ToyCiphertext, witness: &[i64]) -> i64 {
    assert_eq!(
        ciphertext.u.len(),
        witness.len(),
        "ciphertext and witness dimensions must match"
    );

    centered_mod_q(
        ciphertext.v - dot_product_mod_q(&ciphertext.u, witness, Q),
        Q,
    )
}

/// Decrypts a ciphertext or aggregate with a witness for `tag`.
///
/// This checks that the caller-provided tag matches the tag identifier stored
/// in the ciphertext. It is API-level protection, not cryptographic
/// authentication. A real scheme requires a secure GPV trapdoor and
/// short-preimage extraction.
pub fn decrypt_bit(
    ciphertext: &ToyCiphertext,
    tag: &[u8],
    witness: &[i64],
) -> Result<bool, PrototypeError> {
    if ciphertext.tag_id != tag_id(tag) {
        return Err(PrototypeError::TagMismatch);
    }

    Ok(decryption_phase(ciphertext, witness).abs() > DECODE_BOUND)
}

fn sample_small_vector(seed: u64) -> Vec<i64> {
    (0..DIMENSION)
        .map(|index| sample_small_scalar(seed.wrapping_add(index as u64)))
        .collect()
}

fn sample_small_scalar(seed: u64) -> i64 {
    match mix(seed) % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::{
        DECODE_BOUND, PrototypeError, Q, ToyCiphertext, aggregate, decrypt_bit, decryption_phase,
        encrypt_bit, extract_test_witness, is_within_noise_budget,
    };

    #[test]
    fn encrypt_then_decrypts_zero() {
        let tag = b"epoch:42";
        let ciphertext = encrypt_bit(false, tag, 1);
        let witness = extract_test_witness(tag);

        assert!(
            !decrypt_bit(&ciphertext, tag, &witness)
                .expect("ciphertext and witness use the same tag")
        );
    }

    #[test]
    fn encrypt_then_decrypts_one() {
        let tag = b"epoch:42";
        let ciphertext = encrypt_bit(true, tag, 2);
        let witness = extract_test_witness(tag);

        assert!(
            decrypt_bit(&ciphertext, tag, &witness)
                .expect("ciphertext and witness use the same tag")
        );
    }

    #[test]
    fn aggregate_decrypts_to_xor_of_bits() {
        let tag = b"epoch:42";
        let ciphertexts = [
            encrypt_bit(true, tag, 11),
            encrypt_bit(false, tag, 12),
            encrypt_bit(true, tag, 13),
            encrypt_bit(true, tag, 14),
        ];

        let aggregate_ciphertext = aggregate(&ciphertexts).expect("ciphertexts use the same tag");
        let witness = extract_test_witness(tag);

        assert!(
            decrypt_bit(&aggregate_ciphertext, tag, &witness)
                .expect("aggregate and witness use the same tag")
        );
    }

    #[test]
    fn even_number_of_ones_decrypts_to_zero() {
        let tag = b"epoch:42";
        let ciphertexts = [
            encrypt_bit(true, tag, 21),
            encrypt_bit(true, tag, 22),
            encrypt_bit(false, tag, 23),
            encrypt_bit(false, tag, 24),
        ];

        let aggregate_ciphertext = aggregate(&ciphertexts).expect("ciphertexts use the same tag");
        let witness = extract_test_witness(tag);

        assert!(
            !decrypt_bit(&aggregate_ciphertext, tag, &witness)
                .expect("aggregate and witness use the same tag")
        );
    }

    #[test]
    fn distinct_tags_produce_distinct_prototype_witnesses() {
        let witness_a = extract_test_witness(b"epoch:42");
        let witness_b = extract_test_witness(b"epoch:43");

        assert_ne!(witness_a, witness_b);
    }

    #[test]
    fn aggregation_rejects_mixed_tags() {
        let first = encrypt_bit(true, b"epoch:42", 1);
        let second = encrypt_bit(false, b"epoch:43", 2);

        assert_eq!(aggregate(&[first, second]), Err(PrototypeError::MixedTags));
    }

    #[test]
    fn decryption_rejects_a_mismatched_tag() {
        let encryption_tag = b"epoch:42";
        let supplied_tag = b"epoch:43";

        let ciphertext = encrypt_bit(true, encryption_tag, 1);
        let wrong_witness = extract_test_witness(supplied_tag);

        assert_eq!(
            decrypt_bit(&ciphertext, supplied_tag, &wrong_witness),
            Err(PrototypeError::TagMismatch)
        );
    }

    #[test]
    fn decoding_boundary_is_explicit() {
        assert!(is_within_noise_budget(DECODE_BOUND - 1));
        assert!(is_within_noise_budget(-(DECODE_BOUND - 1)));
        assert!(!is_within_noise_budget(DECODE_BOUND));
        assert!(!is_within_noise_budget(-DECODE_BOUND));
    }

    #[test]
    fn excessive_error_can_flip_a_zero_bit() {
        let tag = b"epoch:42";
        let witness = extract_test_witness(tag);
        let valid = encrypt_bit(false, tag, 500);

        let tampered = ToyCiphertext {
            tag_id: valid.tag_id,
            u: valid.u.clone(),
            v: (valid.v + (Q / 2)).rem_euclid(Q),
        };

        assert!(!decrypt_bit(&valid, tag, &witness).expect("valid tag binding"));
        assert!(decrypt_bit(&tampered, tag, &witness).expect("valid tag binding"));

        let phase = decryption_phase(&valid, &witness);
        assert!(phase.abs() < DECODE_BOUND);
    }
}
