//! Domain types for the ECDSA affine-relation attack.
//!
//! These types encode invariants at construction time so that invalid
//! states (swapped signatures, negative step, inconsistent ranges) are
//! unrepresentable.

use crate::error::{RangeError, Result};
use k256::Scalar;

/// A single ECDSA signature component triplet.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    /// R coordinate.
    pub r: Scalar,
    /// S value.
    pub s: Scalar,
    /// Message hash (z).
    pub z: Scalar,
}

impl Signature {
    /// Create a new signature triplet.
    #[must_use]
    pub const fn new(r: Scalar, s: Scalar, z: Scalar) -> Self {
        Self { r, s, z }
    }
}

/// A pair of signatures that share the same private key and nonces related
/// by `k2 = k1 + delta`.
#[derive(Debug, Clone, Copy)]
pub struct SignaturePair {
    /// First signature.
    pub first: Signature,
    /// Second signature.
    pub second: Signature,
}

impl SignaturePair {
    /// Create a new signature pair.
    #[must_use]
    pub const fn new(first: Signature, second: Signature) -> Self {
        Self { first, second }
    }
}

/// Validated search specification.
///
/// Invariants enforced at construction:
/// - `step > 0`
/// - `end >= start`
#[derive(Debug, Clone, Copy)]
pub struct SearchSpec {
    /// Inclusive lower bound of the delta search range.
    pub start: i128,
    /// Inclusive upper bound of the delta search range.
    pub end: i128,
    /// Step size between successive delta candidates.
    pub step: i128,
}

impl SearchSpec {
    /// Create a new `SearchSpec`, validating invariants.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::StepNotPositive`] or [`RangeError::EndBeforeStart`]
    /// if the invariants are violated.
    pub fn new(start: i128, end: i128, step: i128) -> Result<Self> {
        if step <= 0 {
            return Err(RangeError::StepNotPositive.into());
        }
        if end < start {
            return Err(RangeError::EndBeforeStart.into());
        }
        Ok(Self { start, end, step })
    }

    /// Total number of candidates: `floor((end - start) / step) + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::RangeOverflow`] or [`RangeError::RangeTooLarge`]
    /// if the computation overflows.
    pub fn total(&self) -> Result<u128> {
        let span = self
            .end
            .checked_sub(self.start)
            .ok_or(RangeError::RangeOverflow)?;
        (span.cast_unsigned() / self.step.cast_unsigned())
            .checked_add(1)
            .ok_or_else(|| RangeError::RangeTooLarge.into())
    }
}

/// Outcome of a search executed by [`crate::search::SearchEngine`].
#[derive(Debug, Clone, Copy)]
pub struct SearchOutcome {
    /// The discovered delta, or `None` if the search completed without a match.
    pub delta: Option<i128>,
    /// Affine coefficient `alpha`.
    pub alpha: Scalar,
    /// Affine intercept `beta`.
    pub beta: Scalar,
}

impl SearchOutcome {
    /// Construct a new outcome.
    #[must_use]
    pub const fn new(delta: Option<i128>, alpha: Scalar, beta: Scalar) -> Self {
        Self { delta, alpha, beta }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_spec_step_not_positive() {
        let err = SearchSpec::new(0, 10, 0).unwrap_err();
        assert!(err.to_string().contains("step must be > 0"));
    }

    #[test]
    fn test_search_spec_end_before_start() {
        let err = SearchSpec::new(10, 0, 1).unwrap_err();
        assert!(err.to_string().contains("end must be >= start"));
    }

    #[test]
    fn test_search_spec_valid() {
        let spec = SearchSpec::new(-5, 5, 1).unwrap();
        assert_eq!(spec.total().unwrap(), 11);
    }
}
