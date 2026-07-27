//! Small, checked modular-arithmetic helpers for lattice experiments.
//!
//! These functions are not constant-time and are not for production use.

/// Returns `value mod modulus` as a canonical representative in `[0, modulus)`.
///
/// # Panics
///
/// Panics if `modulus <= 0`.
pub fn mod_q(value: i64, modulus: i64) -> i64 {
    assert!(modulus > 0, "modulus must be positive");
    value.rem_euclid(modulus)
}

/// Maps a value modulo `modulus` to its centered representative.
///
/// For an odd modulus `q`, the result lies in `[-floor(q/2), floor(q/2)]`.
///
/// # Panics
///
/// Panics if `modulus <= 0`.
pub fn centered_mod_q(value: i64, modulus: i64) -> i64 {
    assert!(modulus > 0, "modulus must be positive");

    let reduced = mod_q(value, modulus);
    let half = modulus / 2;

    if reduced > half {
        reduced - modulus
    } else {
        reduced
    }
}

/// Adds equal-length vectors coordinate-wise modulo `modulus`.
///
/// # Panics
///
/// Panics if the vectors have different lengths or `modulus <= 0`.
pub fn add_vec_mod_q(left: &[i64], right: &[i64], modulus: i64) -> Vec<i64> {
    assert_eq!(left.len(), right.len(), "vectors must have the same length");

    left.iter()
        .zip(right)
        .map(|(&a, &b)| mod_q(a + b, modulus))
        .collect()
}

/// Computes the inner product of two equal-length vectors modulo `modulus`.
///
/// # Panics
///
/// Panics if the vectors have different lengths or `modulus <= 0`.
pub fn dot_product_mod_q(left: &[i64], right: &[i64], modulus: i64) -> i64 {
    assert!(modulus > 0, "modulus must be positive");
    assert_eq!(left.len(), right.len(), "vectors must have the same length");

    let sum = left
        .iter()
        .zip(right)
        .fold(0_i64, |acc, (&a, &b)| acc + a * b);

    mod_q(sum, modulus)
}

/// Computes `matrix * vector` modulo `modulus`.
///
/// The matrix is represented as rows. Every row must have the same length
/// as `vector`.
///
/// # Panics
///
/// Panics if `matrix` is empty, a row has the wrong length, or `modulus <= 0`.
pub fn matrix_vector_mul_mod_q(matrix: &[Vec<i64>], vector: &[i64], modulus: i64) -> Vec<i64> {
    assert!(modulus > 0, "modulus must be positive");
    assert!(!matrix.is_empty(), "matrix must not be empty");

    matrix
        .iter()
        .map(|row| {
            assert_eq!(
                row.len(),
                vector.len(),
                "every matrix row must match the vector length"
            );
            dot_product_mod_q(row, vector, modulus)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{add_vec_mod_q, centered_mod_q, dot_product_mod_q, matrix_vector_mul_mod_q, mod_q};

    #[test]
    fn mod_q_returns_canonical_representatives() {
        assert_eq!(mod_q(0, 17), 0);
        assert_eq!(mod_q(16, 17), 16);
        assert_eq!(mod_q(17, 17), 0);
        assert_eq!(mod_q(20, 17), 3);
        assert_eq!(mod_q(-1, 17), 16);
        assert_eq!(mod_q(-20, 17), 14);
    }

    #[test]
    fn centered_mod_q_uses_short_signed_representatives() {
        let q = 17;

        assert_eq!(centered_mod_q(0, q), 0);
        assert_eq!(centered_mod_q(8, q), 8);
        assert_eq!(centered_mod_q(9, q), -8);
        assert_eq!(centered_mod_q(16, q), -1);
        assert_eq!(centered_mod_q(-1, q), -1);
        assert_eq!(centered_mod_q(-9, q), 8);
    }

    #[test]
    fn vector_addition_reduces_each_coordinate() {
        assert_eq!(add_vec_mod_q(&[16, 4, -2], &[3, 15, 5], 17), vec![2, 2, 3]);
    }

    #[test]
    fn dot_product_reduces_modulo_q() {
        let q = 17;

        // 2*4 + 3*5 + (-1)*6 = 17 = 0 mod 17.
        assert_eq!(dot_product_mod_q(&[2, 3, -1], &[4, 5, 6], q), 0);

        // 16*2 + 4*3 = 44 = 10 mod 17.
        assert_eq!(dot_product_mod_q(&[16, 4], &[2, 3], q), 10);
    }

    #[test]
    fn matrix_vector_multiplication_reduces_each_row() {
        let q = 17;
        let matrix = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let vector = vec![2, 3, 4];

        // Row 1: 1*2 + 2*3 + 3*4 = 20 = 3 mod 17.
        // Row 2: 4*2 + 5*3 + 6*4 = 47 = 13 mod 17.
        assert_eq!(matrix_vector_mul_mod_q(&matrix, &vector, q), vec![3, 13]);
    }
}
