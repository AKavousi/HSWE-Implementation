use thiserror::Error;

/// Errors returned by HSWE v0.1 public APIs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HsweError {
    #[error("unsupported HSWE parameter configuration")]
    UnsupportedParameters,

    #[error("incompatible HSWE parameters")]
    IncompatibleParameters,

    #[error("invalid parameter identifier")]
    InvalidParameterId,

    #[error("invalid tag encoding")]
    InvalidTagEncoding,

    #[error("unsupported tag kind")]
    UnsupportedTagKind,

    #[error("input exceeds the configured size limit")]
    InputTooLarge,

    #[error("message is outside the configured range")]
    MessageOutOfRange,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid tag signature")]
    InvalidSignature,

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("invalid aggregate")]
    InvalidAggregate,

    #[error("cannot aggregate an empty collection")]
    EmptyAggregate,

    #[error("ciphertexts or aggregates use different tags")]
    IncompatibleTags,

    #[error("aggregate item count overflowed")]
    ItemCountOverflow,

    #[error("lookup table does not match the supplied parameters")]
    LookupTableMismatch,

    #[error("target-group value is outside the discrete-log lookup range")]
    DiscreteLogOutOfRange,

    #[error("unsupported serialized object version")]
    UnsupportedVersion,

    #[error("unexpected serialized object type")]
    UnexpectedObjectType,

    #[error("malformed serialized object")]
    MalformedSerialization,

    #[error("cryptographic randomness could not be obtained")]
    RandomnessFailure,

    #[error("requested operation exceeds a configured resource limit")]
    ResourceLimitExceeded,
}

/// Convenient result type used throughout this crate.
pub type Result<T> = core::result::Result<T, HsweError>;
