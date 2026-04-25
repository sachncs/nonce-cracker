//! Structured error types used throughout the crate.
//!
//! `Error` is a domain-specific enum rather than a string wrapper.
//! Callers can match on variants programmatically, and the `?` operator
//! works transparently through `From` implementations.

use crate::config::ConfigError;

/// Top-level error enum returned by all public operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// Search range or step was invalid.
    #[error("range error: {0}")]
    Range(#[from] RangeError),
    /// I/O operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Hex decoding failed.
    #[error("hex parse error: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Integer parsing failed.
    #[error("parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),
    /// Configuration loading failed.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    /// Internal search-engine failure.
    #[error("search error: {0}")]
    Engine(#[from] EngineError),
}

/// Errors originating in the cryptographic domain.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// `s1` has no multiplicative inverse.
    #[error("s1 not invertible")]
    S1NotInvertible,
    /// The denominator `a = s2/s1 * r1 - r2` has no inverse.
    #[error("denominator not invertible")]
    DenominatorNotInvertible,
    /// Parsed scalar exceeds the field range.
    #[error("scalar out of range")]
    ScalarOutOfRange,
    /// Empty or whitespace-only hex string.
    #[error("empty hex string")]
    EmptyHexString,
    /// Hex string decodes to more than 32 bytes.
    #[error("scalar exceeds 32 bytes")]
    ScalarExceeds32Bytes,
    /// Public key encoding is longer than 65 bytes.
    #[error("pubkey exceeds 65 bytes")]
    PubkeyExceeds65Bytes,
    /// Public key prefix is not `02`, `03`, or `04`.
    #[error("invalid pubkey encoding: {0}")]
    InvalidPubkeyEncoding(String),
    /// SEC1 parser rejected the public key.
    #[error("pubkey parse error: {0}")]
    PubkeyParse(String),
}

/// Errors related to search range invariants.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `end` is less than `start`.
    #[error("end must be >= start")]
    EndBeforeStart,
    /// `end - start` overflowed `i128`.
    #[error("range overflow")]
    RangeOverflow,
    /// Total candidate count exceeded `u128::MAX`.
    #[error("range too large")]
    RangeTooLarge,
    /// Step size is zero or negative.
    #[error("step must be > 0")]
    StepNotPositive,
    /// Thread count was explicitly set to zero.
    #[error("threads must be > 0")]
    ThreadsNotPositive,
    /// Output file path is empty or whitespace.
    #[error("outfile must not be empty")]
    EmptyOutfile,
    /// Parsed magnitude exceeds the range of `i128`.
    #[error("value overflows i128")]
    I128Overflow,
}

/// Internal search engine errors.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Rayon thread pool failed to initialise.
    #[error("thread pool: {0}")]
    ThreadPoolInit(String),
    /// The BSGS `m` parameter overflows `u64`.
    #[error("BSGS m overflow")]
    BsgsMOverflow,
    /// The BSGS segment length overflows `u64`.
    #[error("BSGS segment length overflow")]
    BsgsSegmentOverflow,
    /// Giant-step chunk boundary conversion failed.
    #[error("giant-step chunk boundary overflow")]
    GsChunkOverflow,
    /// Giant-step coefficient conversion failed.
    #[error("giant-step coefficient overflow")]
    GsCoeffOverflow,
}

/// Convenience alias used by every public function in this crate.
pub type Result<T> = std::result::Result<T, Error>;
