//! High-performance ECDSA private key recovery for secp256k1
//!
//! Recovers a private key from two signatures where the nonces satisfy k₂ = k₁ + δ,
//! with δ unknown but bounded. Uses the formula:
//!
//! d(δ) = (s₁z₂ - s₂z₁ - s₁s₂δ)(s₂r₁ - s₁r₂)⁻¹ mod n
//!
//! Which simplifies to the linear form: d(δ) = d0 - δ·step

use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// 32-byte scalar type alias
pub type Scalar32 = [u8; 32];

/// Convert a byte array to a Scalar, returning None if invalid
#[inline]
fn bytes_to_scalar(bytes: &Scalar32) -> Option<Scalar> {
    Scalar::from_repr(bytes.clone().into()).into()
}

/// Core parameters for the recovery formula d(δ) = d0 - δ·step
///
/// The formula is derived from ECDSA signature relations:
/// - denom = (s₂r₁ - s₁r₂) mod n
/// - A = (s₁z₂ - s₂z₁) mod n
/// - B = s₁s₂ mod n
///
/// Then: d(δ) = (A - B·δ) · denom⁻¹ mod n = d0 - δ·step
#[derive(Debug, Clone)]
pub struct RecoveryParams {
    /// d0 = (s₁z₂ - s₂z₁) · (s₂r₁ - s₁r₂)⁻¹ mod n
    pub d0: Scalar,
    /// step = s₁s₂ · (s₂r₁ - s₁r₂)⁻¹ mod n
    pub step: Scalar,
}

impl RecoveryParams {
    /// Compute recovery parameters from two ECDSA signatures
    ///
    /// Returns None if the denominator is zero (invalid signature pair).
    pub fn from_signatures(
        r1: &Scalar32,
        s1: &Scalar32,
        z1: &Scalar32,
        r2: &Scalar32,
        s2: &Scalar32,
        z2: &Scalar32,
    ) -> Option<Self> {
        let r1_val = bytes_to_scalar(r1)?;
        let s1_val = bytes_to_scalar(s1)?;
        let z1_val = bytes_to_scalar(z1)?;
        let r2_val = bytes_to_scalar(r2)?;
        let s2_val = bytes_to_scalar(s2)?;
        let z2_val = bytes_to_scalar(z2)?;

        // denom = (s₂r₁ - s₁r₂) mod n
        let denom: Scalar = s2_val * r1_val - s1_val * r2_val;

        // Check for zero denominator
        if denom == Scalar::ZERO {
            return None;
        }

        let denom_inv = denom.invert().unwrap();

        // A = (s₁z₂ - s₂z₁) mod n
        let a: Scalar = s1_val * z2_val - s2_val * z1_val;

        // B = s₁s₂ mod n
        let b: Scalar = s1_val * s2_val;

        // d0 = A · denom_inv mod n
        let d0: Scalar = a * denom_inv;

        // step = B · denom_inv mod n
        let step: Scalar = b * denom_inv;

        Some(Self { d0, step })
    }

    /// Compute d(δ) = d0 - δ·step mod n
    #[inline(always)]
    pub fn compute_d(&self, delta: u64) -> Scalar {
        let delta_scalar = Scalar::from(delta);
        self.d0 - delta_scalar * self.step
    }

    /// Compute d(δ) for signed delta
    #[inline(always)]
    pub fn compute_d_signed(&self, delta: i64) -> Scalar {
        let delta_scalar = Scalar::from(delta.unsigned_abs());
        if delta < 0 {
            self.d0 + delta_scalar * self.step
        } else {
            self.d0 - delta_scalar * self.step
        }
    }
}

/// Recover private key d for a given delta using the core formula
///
/// d(δ) = (s₁z₂ - s₂z₁ - s₁s₂δ)(s₂r₁ - s₁r₂)⁻¹ mod n
///
/// Returns None if denom = 0 (invalid signature pair).
#[inline]
pub fn recover_d_from_delta(
    r1: &Scalar32,
    s1: &Scalar32,
    z1: &Scalar32,
    r2: &Scalar32,
    s2: &Scalar32,
    z2: &Scalar32,
    delta: u64,
) -> Option<Scalar> {
    let params = RecoveryParams::from_signatures(r1, s1, z1, r2, s2, z2)?;
    Some(params.compute_d(delta))
}

/// Compute public key Q = d · G
#[inline]
pub fn compute_public_key(d: &Scalar) -> AffinePoint {
    (ProjectivePoint::GENERATOR * d).to_affine()
}

/// Check if computed public key matches the target (full affine comparison)
#[inline]
pub fn matches_public_key_full(d: &Scalar, target: &PublicKey) -> bool {
    let computed = compute_public_key(d);
    let target_affine = target.as_affine();
    computed == *target_affine
}

/// Check if computed public key matches target x-coordinate only (faster)
#[inline]
pub fn matches_public_key_x(d: &Scalar, target_x: &Scalar32) -> bool {
    let computed = compute_public_key(d);
    computed.to_encoded_point(false).x().map(|x| x.as_ref()) == Some(target_x)
}

/// Target public key representation for matching
#[derive(Clone)]
pub enum TargetPublicKey {
    /// Full public key for exact comparison
    Full(PublicKey),
    /// X-coordinate only
    XOnly(Scalar32),
}

impl TargetPublicKey {
    /// Create from various public key formats
    pub fn from_hex(hex: &str) -> Result<Self, ()> {
        let bytes = parse_hex(hex).map_err(|_| ())?;
        match bytes.first() {
            Some(0x02) | Some(0x03) => {
                // Compressed - extract x
                if bytes.len() != 33 {
                    return Err(());
                }
                let mut x = [0u8; 32];
                x.copy_from_slice(&bytes[1..33]);
                Ok(Self::XOnly(x))
            }
            Some(0x04) => {
                // Uncompressed
                if bytes.len() != 65 {
                    return Err(());
                }
                PublicKey::from_sec1_bytes(&bytes)
                    .map(Self::Full)
                    .map_err(|_| ())
            }
            _ if bytes.len() == 32 => {
                // Raw x-coordinate
                let mut x = [0u8; 32];
                x.copy_from_slice(&bytes);
                Ok(Self::XOnly(x))
            }
            _ => Err(()),
        }
    }

    /// Check if a private key matches this target
    #[inline]
    pub fn matches(&self, d: &Scalar) -> bool {
        match self {
            Self::Full(pk) => matches_public_key_full(d, pk),
            Self::XOnly(x) => matches_public_key_x(d, x),
        }
    }

    /// Check if a point's x-coordinate matches this target (for internal use)
    #[inline]
    pub fn matches_x_coordinate(&self, x_bytes: &[u8; 32]) -> bool {
        match self {
            Self::Full(pk) => {
                let encoded = pk.to_encoded_point(false);
                encoded.x().map(|x| x.as_ref()) == Some(x_bytes)
            }
            Self::XOnly(x) => x == x_bytes,
        }
    }
}

/// Parallel brute-force search over delta range (unsigned)
///
/// Searches δ ∈ [start, end) and returns the first match.
pub fn brute_force_delta_parallel(
    r1: &Scalar32,
    s1: &Scalar32,
    z1: &Scalar32,
    r2: &Scalar32,
    s2: &Scalar32,
    z2: &Scalar32,
    start: u64,
    end: u64,
    target: &TargetPublicKey,
    chunk_size: u64,
) -> Option<Scalar> {
    // Precompute all invariants once
    let params = RecoveryParams::from_signatures(r1, s1, z1, r2, s2, z2)?;

    let found = AtomicBool::new(false);
    let result = std::sync::Mutex::new(None::<Scalar>);

    // Total iterations
    let total = end.saturating_sub(start);
    if total == 0 {
        return None;
    }

    // Chunk the work
    let chunks: Vec<(u64, u64)> = (start..end)
        .step_by(chunk_size as usize)
        .map(|chunk_start| {
            let chunk_end = (chunk_start + chunk_size).min(end);
            (chunk_start, chunk_end)
        })
        .collect();

    chunks.into_par_iter().for_each(|(chunk_start, chunk_end)| {
        if found.load(Ordering::Acquire) {
            return;
        }

        // Compute starting d for this chunk: d(start) = d0 - start*step
        let mut d = params.d0;
        if chunk_start > 0 {
            d = d - Scalar::from(chunk_start) * params.step;
        }

        let mut delta = chunk_start;
        while delta < chunk_end {
            if found.load(Ordering::Acquire) {
                break;
            }

            if target.matches(&d) {
                if !found.swap(true, Ordering::AcqRel) {
                    let mut res = result.lock().unwrap();
                    *res = Some(d);
                }
                break;
            }

            // Advance: d = d - step
            d = d - params.step;
            delta += 1;
        }
    });

    result.into_inner().unwrap()
}

/// High-performance parallel search with configurable thread count (unsigned)
///
/// Searches δ ∈ [start, end) and returns the first match.
pub fn brute_force_delta_parallel_with_threads(
    r1: &Scalar32,
    s1: &Scalar32,
    z1: &Scalar32,
    r2: &Scalar32,
    s2: &Scalar32,
    z2: &Scalar32,
    start: u64,
    end: u64,
    target: &TargetPublicKey,
    threads: usize,
    chunk_size: u64,
) -> Option<Scalar> {
    let params = RecoveryParams::from_signatures(r1, s1, z1, r2, s2, z2)?;

    let total = end.saturating_sub(start);
    if total == 0 {
        return None;
    }

    let found = AtomicBool::new(false);
    let result = std::sync::Mutex::new(None::<Scalar>);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .ok()?;

    pool.install(|| {
        (start..end)
            .step_by(chunk_size as usize)
            .map(|chunk_start| (chunk_start, (chunk_start + chunk_size).min(end)))
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|(chunk_start, chunk_end)| {
                if found.load(Ordering::Acquire) {
                    return;
                }

                // Compute d at chunk_start
                let mut d = params.d0;
                if chunk_start > 0 {
                    d = d - Scalar::from(chunk_start) * params.step;
                }

                let mut delta = chunk_start;
                while delta < chunk_end {
                    if found.load(Ordering::Acquire) {
                        break;
                    }

                    if target.matches(&d) {
                        if !found.swap(true, Ordering::AcqRel) {
                            let mut res = result.lock().unwrap();
                            *res = Some(d);
                        }
                        break;
                    }

                    d = d - params.step;
                    delta += 1;
                }
            });
    });

    result.into_inner().unwrap()
}

/// Parallel brute-force search over signed delta range
///
/// Searches δ ∈ [start, end] (inclusive) with signed deltas and returns (delta, d).
pub fn brute_force_delta_parallel_signed(
    r1: &Scalar32,
    s1: &Scalar32,
    z1: &Scalar32,
    r2: &Scalar32,
    s2: &Scalar32,
    z2: &Scalar32,
    start: i64,
    end: i64,
    target: &TargetPublicKey,
    threads: usize,
    chunk_size: u64,
) -> Option<(i64, Scalar)> {
    let params = RecoveryParams::from_signatures(r1, s1, z1, r2, s2, z2)?;

    if end < start {
        return None;
    }

    let span = end as i128 - start as i128;
    if span < 0 {
        return None;
    }
    let total: u64 = (span as u64) + 1;
    if total == 0 {
        return None;
    }

    let found = AtomicBool::new(false);
    let result = std::sync::Mutex::new(None::<(i64, Scalar)>);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .ok()?;

    pool.install(|| {
        (start..=end)
            .step_by(chunk_size as usize)
            .map(|chunk_start| {
                let chunk_end = (chunk_start as i64 + chunk_size as i64 - 1).min(end);
                (chunk_start, chunk_end)
            })
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|(chunk_start, chunk_end)| {
                if found.load(Ordering::Acquire) {
                    return;
                }

                // Compute d at chunk_start
                let mut d = params.compute_d_signed(chunk_start);

                let mut delta = chunk_start;
                while delta <= chunk_end {
                    if found.load(Ordering::Acquire) {
                        break;
                    }

                    if target.matches(&d) {
                        if !found.swap(true, Ordering::AcqRel) {
                            let mut res = result.lock().unwrap();
                            *res = Some((delta, d));
                        }
                        break;
                    }

                    d = params.compute_d_signed(delta + 1);
                    delta += 1;
                }
            });
    });

    result.into_inner().unwrap()
}

/// Parse a hex string into bytes
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, ()> {
    let hex = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if hex.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ())?;
        bytes.push(b);
    }
    Ok(bytes)
}

/// Convert scalar to hex string
pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that denom = 0 case returns None
    #[test]
    fn test_denom_zero_returns_none() {
        // When s2*r1 == s1*r2, denom = 0
        let r1: Scalar32 = [1; 32];
        let s1: Scalar32 = [2; 32];
        let z1: Scalar32 = [1; 32];
        let r2: Scalar32 = [1; 32];  // Same r1
        let s2: Scalar32 = [2; 32];  // Same s1
        let z2: Scalar32 = [2; 32];

        // denom = s2*r1 - s1*r2 = 2*1 - 2*1 = 0
        let result = RecoveryParams::from_signatures(&r1, &s1, &z1, &r2, &s2, &z2);
        assert!(result.is_none());
    }

    /// Test compute_d with delta = 0
    #[test]
    fn test_compute_d_delta_zero() {
        let r1: Scalar32 = [1; 32];
        let s1: Scalar32 = [1; 32];
        let z1: Scalar32 = [1; 32];
        let r2: Scalar32 = [2; 32];
        let s2: Scalar32 = [1; 32];
        let z2: Scalar32 = [2; 32];

        let params = RecoveryParams::from_signatures(&r1, &s1, &z1, &r2, &s2, &z2).unwrap();

        // d(0) should equal d0
        let d0 = params.compute_d(0);
        assert_eq!(d0, params.d0);
    }

    /// Test public key computation and matching
    #[test]
    fn test_public_key_computation() {
        // Known private key d = 0x3039
        let d = Scalar::from(0x3039u64);
        let _pk = compute_public_key(&d);

        // Verify with known public key
        let known_pk_hex = "03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f";
        let target = TargetPublicKey::from_hex(known_pk_hex).unwrap();
        assert!(target.matches(&d));
    }

    /// Test x-only matching
    #[test]
    fn test_x_only_matching() {
        let d = Scalar::from(0x3039u64);
        let pk = compute_public_key(&d);
        let encoded = pk.to_encoded_point(false);
        let x_ref: &[u8; 32] = encoded.x().map(|x| x.as_ref()).unwrap();

        // Should match
        assert!(matches_public_key_x(&d, x_ref));

        // Wrong x should not match
        let mut wrong_x = *x_ref;
        wrong_x[0] ^= 0xFF;
        assert!(!matches_public_key_x(&d, &wrong_x));
    }

    /// Test parsing various public key formats
    #[test]
    fn test_target_public_key_parsing() {
        // Compressed
        let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(TargetPublicKey::from_hex(compressed).is_ok());

        // X-only
        let xonly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(TargetPublicKey::from_hex(xonly).is_ok());

        // Raw 32 bytes
        assert!(TargetPublicKey::from_hex(xonly).is_ok());
    }

    /// Test that search returns None when delta is out of range
    #[test]
    fn test_search_out_of_range() {
        let r1: Scalar32 = [1; 32];
        let s1: Scalar32 = [1; 32];
        let z1: Scalar32 = [1; 32];
        let r2: Scalar32 = [2; 32];
        let s2: Scalar32 = [1; 32];
        let z2: Scalar32 = [2; 32];

        // Use a target that won't be found
        let wrong_x: Scalar32 = [0xFF; 32];
        let target = TargetPublicKey::XOnly(wrong_x);

        let result = brute_force_delta_parallel(
            &r1, &s1, &z1, &r2, &s2, &z2,
            0, 100,
            &target,
            1000,
        );

        assert!(result.is_none());
    }

    /// Test signed delta computation
    #[test]
    fn test_compute_d_signed() {
        let r1: Scalar32 = [1; 32];
        let s1: Scalar32 = [1; 32];
        let z1: Scalar32 = [1; 32];
        let r2: Scalar32 = [2; 32];
        let s2: Scalar32 = [1; 32];
        let z2: Scalar32 = [2; 32];

        let params = RecoveryParams::from_signatures(&r1, &s1, &z1, &r2, &s2, &z2).unwrap();

        // d(0) should equal d0
        let d0 = params.compute_d_signed(0);
        assert_eq!(d0, params.d0);

        // d(1) = d0 - step
        let d1 = params.compute_d_signed(1);
        let expected = params.d0 - params.step;
        assert_eq!(d1, expected);

        // d(-1) = d0 + step
        let d_neg1 = params.compute_d_signed(-1);
        let expected_neg = params.d0 + params.step;
        assert_eq!(d_neg1, expected_neg);
    }
}