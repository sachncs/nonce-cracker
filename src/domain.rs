//! Domain types for the ECDSA affine-relation attack.
//!
//! These types encode invariants at construction time so that invalid
//! states (swapped signatures, negative step, inconsistent ranges) are
//! unrepresentable.

use crate::error::{RangeError, Result};
use k256::Scalar;
use zeroize::Zeroize;

/// A single ECDSA signature component triplet.
///
/// Not `Copy` so that secrets are cleared from memory on drop.
#[derive(Debug, Clone)]
pub struct Signature {
    /// R coordinate.
    pub r: Scalar,
    /// S value.
    pub s: Scalar,
    /// Message hash (z).
    pub z: Scalar,
}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        // k256::Scalar does not expose its internal bytes, but we can
        // overwrite the scalar by reassigning from zero.
        self.r = Scalar::ZERO;
        self.s = Scalar::ZERO;
        self.z = Scalar::ZERO;
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Signature {
    /// Create a new signature triplet.
    #[must_use]
    pub const fn new(r: Scalar, s: Scalar, z: Scalar) -> Self {
        Self { r, s, z }
    }
}

/// Validated search specification.
///
/// Invariants enforced at construction:
/// - `step > 0`
/// - `end >= start`
#[derive(Debug, Clone, Copy)]
pub struct SearchSpec {
    /// Inclusive lower bound of the nonce search range.
    pub start: i128,
    /// Inclusive upper bound of the nonce search range.
    pub end: i128,
    /// Step size between successive nonce candidates.
    pub step: i128,
}

impl SearchSpec {
    /// Create a new `SearchSpec`, validating invariants.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::StepNotPositive`], [`RangeError::EndBeforeStart`],
    /// or [`RangeError::RangeOverflow`] if the invariants are violated.
    pub fn new(start: i128, end: i128, step: i128) -> Result<Self> {
        if step <= 0 {
            return Err(RangeError::StepNotPositive.into());
        }
        if end < start {
            return Err(RangeError::EndBeforeStart.into());
        }
        let span = end.checked_sub(start).ok_or(RangeError::RangeOverflow)?;
        let n = span / step;
        let _ = start
            .checked_add(n.checked_mul(step).ok_or(RangeError::RangeOverflow)?)
            .ok_or(RangeError::RangeOverflow)?;
        Ok(Self { start, end, step })
    }

    /// Total number of candidates: `floor((end - start) / step) + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::RangeOverflow`] or [`RangeError::RangeTooLarge`]
    /// if the computation overflows.
    /// Hard upper bound on candidate count to prevent absurd ranges.
    const MAX_TOTAL: u128 = 1u128 << 64;

    /// Total number of candidates: `floor((end - start) / step) + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::RangeOverflow`] or [`RangeError::RangeTooLarge`]
    /// if the computation overflows or exceeds the internal guard.
    pub fn total(&self) -> Result<u128> {
        let span = self
            .end
            .checked_sub(self.start)
            .ok_or(RangeError::RangeOverflow)?;
        let total = (span.cast_unsigned() / self.step.cast_unsigned())
            .checked_add(1)
            .ok_or(RangeError::RangeTooLarge)?;
        if total > Self::MAX_TOTAL {
            return Err(RangeError::RangeTooLarge.into());
        }
        Ok(total)
    }
}

/// Outcome of a search executed by [`crate::search::SearchEngine`].
///
/// Not `Copy` or `Clone` so that secrets are cleared from memory on drop.
/// Use references if the outcome must be shared.
#[derive(Debug)]
pub struct SearchOutcome {
    /// The discovered nonce, or `None` if the search completed without a match.
    pub nonce: Option<i128>,
    /// Affine coefficient `alpha`.
    pub alpha: Scalar,
    /// Affine intercept `beta`.
    pub beta: Scalar,
}

impl Zeroize for SearchOutcome {
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.alpha = Scalar::ZERO;
        self.beta = Scalar::ZERO;
    }
}

impl Drop for SearchOutcome {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SearchOutcome {
    /// Construct a new outcome.
    #[must_use]
    pub const fn new(nonce: Option<i128>, alpha: Scalar, beta: Scalar) -> Self {
        Self { nonce, alpha, beta }
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

    #[test]
    fn test_search_spec_range_overflow() {
        let err = SearchSpec::new(i128::MIN, i128::MAX, 1).unwrap_err();
        assert!(err.to_string().contains("overflow"));
    }
}
