//! Public research-prototype API for binary LWE-HSWE algebra.
//!
//! SECURITY WARNING: This module is not production cryptography. It provides
//! a typed interface around the toy algebra in `prototype.rs`.

use super::prototype::{
    PrototypeError, ToyCiphertext, aggregate, decrypt_bit, encrypt_bit, extract_test_witness,
};

/// A public tag under which one or more bits are encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag(Vec<u8>);

impl Tag {
    /// Creates a tag from arbitrary application-defined bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the canonical byte representation of this tag.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A test-only extraction result associated with one tag.
///
/// In a secure GPV implementation, this would contain a short preimage
/// sampled using a master trapdoor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrototypeWitness {
    coordinates: Vec<i64>,
}

impl PrototypeWitness {
    /// Returns the prototype witness coordinates.
    pub fn as_slice(&self) -> &[i64] {
        &self.coordinates
    }
}

/// Encrypts one binary message under `tag`.
pub fn encrypt(bit: bool, tag: &Tag, nonce: u64) -> ToyCiphertext {
    encrypt_bit(bit, tag.as_bytes(), nonce)
}

/// Extracts the test-only witness associated with `tag`.
///
/// This is intentionally insecure: the witness is publicly derivable from the
/// tag because the prototype uses an identity matrix in place of GPV setup.
pub fn extract(tag: &Tag) -> PrototypeWitness {
    PrototypeWitness {
        coordinates: extract_test_witness(tag.as_bytes()),
    }
}

/// Homomorphically XOR-aggregates ciphertexts encrypted under the same tag.
///
/// Returns `PrototypeError::MixedTags` if the ciphertexts belong to different
/// tags, and `PrototypeError::EmptyAggregation` for an empty input.
pub fn evaluate_xor(ciphertexts: &[ToyCiphertext]) -> Result<ToyCiphertext, PrototypeError> {
    aggregate(ciphertexts)
}

/// Decrypts a ciphertext or aggregate using a witness extracted for `tag`.
///
/// Returns `PrototypeError::TagMismatch` if `tag` differs from the ciphertext
/// tag bound at the API level.
pub fn decrypt(
    ciphertext: &ToyCiphertext,
    tag: &Tag,
    witness: &PrototypeWitness,
) -> Result<bool, PrototypeError> {
    decrypt_bit(ciphertext, tag.as_bytes(), witness.as_slice())
}

#[cfg(test)]
mod tests {
    use super::{Tag, decrypt, encrypt, evaluate_xor, extract};
    use crate::lattice::prototype::PrototypeError;

    #[test]
    fn end_to_end_same_tag_xor() {
        let tag = Tag::new(b"round:2026-07-27");
        let witness = extract(&tag);

        let ciphertexts = [
            encrypt(true, &tag, 1),
            encrypt(false, &tag, 2),
            encrypt(true, &tag, 3),
        ];

        let aggregate = evaluate_xor(&ciphertexts).expect("all inputs use one tag");

        // true XOR false XOR true = false.
        assert!(!decrypt(&aggregate, &tag, &witness).expect("ciphertext, tag, and witness match"));
    }

    #[test]
    fn aggregate_parity_matches_many_inputs() {
        let tag = Tag::new(b"round:noise-check");
        let witness = extract(&tag);

        let bits = [
            true, false, true, true, false, false, true, false, true, false, true, false,
        ];

        let ciphertexts: Vec<_> = bits
            .iter()
            .enumerate()
            .map(|(index, &bit)| encrypt(bit, &tag, index as u64 + 100))
            .collect();

        let expected_parity = bits.iter().fold(false, |parity, &bit| parity ^ bit);
        let aggregate = evaluate_xor(&ciphertexts).expect("all inputs use one tag");

        assert_eq!(
            decrypt(&aggregate, &tag, &witness).expect("matching tag"),
            expected_parity
        );
    }

    #[test]
    fn aggregate_rejects_mixed_tags() {
        let first_tag = Tag::new(b"round:1");
        let second_tag = Tag::new(b"round:2");

        let ciphertexts = [encrypt(true, &first_tag, 1), encrypt(false, &second_tag, 2)];

        assert_eq!(evaluate_xor(&ciphertexts), Err(PrototypeError::MixedTags));
    }

    #[test]
    fn decrypt_rejects_mismatched_tag() {
        let ciphertext_tag = Tag::new(b"round:1");
        let supplied_tag = Tag::new(b"round:2");

        let ciphertext = encrypt(true, &ciphertext_tag, 99);
        let witness = extract(&supplied_tag);

        assert_eq!(
            decrypt(&ciphertext, &supplied_tag, &witness),
            Err(PrototypeError::TagMismatch)
        );
    }
}
