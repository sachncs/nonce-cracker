#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! High-speed parallel ECDSA private key recovery for secp256k1 using an affine
//! relation attack on a single signature.
//!
//! This crate provides the core cryptographic operations, search algorithms,
//! configuration, logging, and metrics used by the `nonce-cracker` binary.
//!
//! # Example
//!
//! ```
//! use nonce_cracker::{derive_affine_constants, parse_scalar, Signature, SearchSpec};
//!
//! let sig = Signature::new(parse_scalar("0x1").unwrap(), parse_scalar("0x3").unwrap(), parse_scalar("0x5").unwrap());
//!
//! let (alpha, beta) = derive_affine_constants(&sig).unwrap();
//! ```

mod config;
mod context;
mod crypto;
mod domain;
mod error;
pub mod logging;
mod metrics;
pub mod search;

#[cfg(test)]
pub mod fixtures;

// Stable public API
pub use config::Config;
pub use config::ConfigError;
pub use context::{AppContext, ShutdownToken};
pub use domain::{SearchOutcome, SearchSpec, Signature};
pub use error::{CryptoError, Error, RangeError, Result};
pub use metrics::{MetricsSink, SearchReport, TracingMetricsSink};
pub use search::SearchEngine;

// Cryptographic utilities
pub use crypto::{
    affine_key, derive_affine_constants, derive_private_key, parse_int, parse_pubkey, parse_scalar,
    scalar_hex, verify_ecdsa_signature,
};

// Logging utilities are available via `nonce_cracker::logging`.
