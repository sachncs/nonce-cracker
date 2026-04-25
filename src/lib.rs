//! High-speed parallel ECDSA private key recovery for secp256k1 using an affine
//! relation attack.
//!
//! This crate provides the core cryptographic operations, search algorithms,
//! configuration, logging, and metrics used by the `nonce-cracker` binary.
//!
//! # Example
//!
//! ```
//! use nonce_cracker::{derive_affine_constants, parse_scalar, Signature, SignaturePair, SearchSpec};
//!
//! let sig1 = Signature::new(parse_scalar("0x1").unwrap(), parse_scalar("0x3").unwrap(), parse_scalar("0x5").unwrap());
//! let sig2 = Signature::new(parse_scalar("0x2").unwrap(), parse_scalar("0x4").unwrap(), parse_scalar("0x6").unwrap());
//! let pair = SignaturePair::new(sig1, sig2);
//!
//! let (alpha, beta) = derive_affine_constants(&pair).unwrap();
//! ```

mod config;
mod context;
mod crypto;
mod domain;
mod error;
mod logging;
mod metrics;
mod search;

// Stable public API
pub use config::Config;
pub use context::{AppContext, ShutdownToken};
pub use domain::{SearchOutcome, SearchSpec, Signature, SignaturePair};
pub use error::{CryptoError, Error, RangeError, Result};
pub use metrics::{MetricsSink, SearchReport, TracingMetricsSink};
pub use search::SearchEngine;

// Cryptographic utilities
pub use crypto::{
    affine_key, derive_affine_constants, derive_private_key, parse_int, parse_pubkey, parse_scalar,
    scalar_hex,
};

// Crate-internal re-exports for main.rs and unit tests
#[doc(hidden)]
pub use logging::{emit_summary, init as init_logging};
