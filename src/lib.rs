//! HSWE v0.1 research prototype.
//!
//! This crate implements the pairing-based Homomorphic Signature-based
//! Witness Encryption construction described in the repository documentation.
//! It is a research artifact and is not suitable for production use.

pub mod aggregation;
pub mod ciphertext;
pub mod decryption;
pub mod encryption;
pub mod error;
pub mod keys;
pub mod lattice;
pub mod lookup;
pub mod params;
pub mod privacy;
pub mod sharing;
pub mod tag;
