//! Cryptographic primitives for the affine-relation attack.
//!
//! This module provides scalar/field parsing, affine constant derivation,
//! ECDSA signature verification, and helper utilities used by the search
//! engine and CLI.

use crate::domain::Signature;
use crate::error::{CryptoError, RangeError, Result};
use zeroize::Zeroize;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature as EcdsaSignature, VerifyingKey},
    elliptic_curve::PrimeField,
    AffinePoint, PublicKey, Scalar,
};

/// Derive the affine constants `alpha` and `beta` from a single ECDSA
/// signature such that the private key can be expressed as:
///
///   `d = alpha * k - beta  (mod n)`
///
/// where `k` is the nonce used to produce the signature.
///
/// # Errors
///
/// Returns [`CryptoError::RNotInvertible`] if `r` has no inverse.
pub fn derive_affine_constants(sig: &Signature) -> Result<(Scalar, Scalar)> {
    let r_inv = sig.r.invert();
    if r_inv.is_none().into() {
        return Err(CryptoError::RNotInvertible.into());
    }
    let mut r_inv = r_inv.unwrap();
    let alpha = r_inv * sig.s;
    let beta = r_inv * sig.z;
    r_inv.zeroize();
    Ok((alpha, beta))
}

/// Compute the candidate private key for a given nonce `k` using the affine
/// relation `d = alpha * k - beta`.
#[inline]
#[must_use]
pub fn derive_private_key(nonce: u128, alpha: Scalar, beta: Scalar) -> Scalar {
    let mut s = Scalar::from(nonce);
    let ak = alpha * s;
    let result = ak - beta;
    s.zeroize();
    result
}

/// Parse a decimal or hex string into a secp256k1 `Scalar`.
///
/// Accepts decimal strings or hex strings with optional `0x`/`0X` prefix.
/// Odd-length hex is zero-padded. Returns an error for empty strings,
/// oversized values (>32 bytes), or values outside the scalar field range.
///
/// # Errors
///
/// Returns [`CryptoError::EmptyInput`], [`CryptoError::ScalarExceeds32Bytes`],
/// or [`CryptoError::ScalarOutOfRange`] for invalid input.
pub fn parse_scalar(s: &str) -> Result<Scalar> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::EmptyInput.into());
    }

    // Detect hex by explicit prefix or presence of hex digits (a-f/A-F).
    let is_hex = trimmed.starts_with("0x")
        || trimmed.starts_with("0X")
        || trimmed.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F'));
    let raw = trimmed.trim_start_matches("0x").trim_start_matches("0X");

    if raw.is_empty() {
        return Err(CryptoError::EmptyInput.into());
    }

    let mut arr = [0u8; 32];

    if is_hex {
        let len = raw.len();
        if len > 64 {
            return Err(CryptoError::ScalarExceeds32Bytes.into());
        }
        let decoded_len = len.div_ceil(2);
        if len % 2 == 1 {
            let mut tmp = [0u8; 65];
            tmp[0] = b'0';
            tmp[1..][..len].copy_from_slice(raw.as_bytes());
            hex::decode_to_slice(&tmp[..=len], &mut arr[32 - decoded_len..])?;
        } else {
            hex::decode_to_slice(raw, &mut arr[32 - decoded_len..])?;
        }
    } else {
        // Parse as decimal: accumulate into big-endian 256-bit integer.
        for ch in raw.chars() {
            let digit = ch.to_digit(10).ok_or(CryptoError::ScalarOutOfRange)? as u16;
            let mut carry = digit;
            for i in (0..32).rev() {
                let val = (arr[i] as u16) * 10 + carry;
                arr[i] = (val & 0xFF) as u8;
                carry = val >> 8;
            }
            if carry != 0 {
                return Err(CryptoError::ScalarExceeds32Bytes.into());
            }
        }
    }

    Option::from(Scalar::from_repr(arr.into())).ok_or_else(|| CryptoError::ScalarOutOfRange.into())
}

/// Verify an ECDSA signature (`r`, `s`) over message hash `z` against `pubkey`.
///
/// Rejects signatures where `r` or `s` is zero or out of range, or where the
/// signature does not mathematically verify against the given public key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if the signature is malformed or
/// fails verification.
pub fn verify_ecdsa_signature(
    pubkey: &PublicKey,
    r: &Scalar,
    s: &Scalar,
    z: &Scalar,
) -> Result<()> {
    let vk = VerifyingKey::from(pubkey);
    let sig = EcdsaSignature::from_scalars(r.to_bytes(), s.to_bytes())
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
    // k256 requires low-S signatures; normalize before verifying.
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify_prehash(z.to_bytes().as_ref(), &sig)
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
    Ok(())
}

/// Parse a hex string into a secp256k1 `PublicKey`.
///
/// Accepts compressed (`02`/`03` + 32-byte x) or uncompressed
/// (`04` + 32-byte x + 32-byte y) SEC1 encoding.
///
/// # Errors
///
/// Returns [`CryptoError::PubkeyExceeds65Bytes`], [`CryptoError::InvalidPubkeyEncoding`],
/// or [`CryptoError::PubkeyParse`] for invalid input.
pub fn parse_pubkey(s: &str) -> Result<PublicKey> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let len = raw.len();
    if len > 130 {
        return Err(CryptoError::PubkeyExceeds65Bytes.into());
    }
    let mut buf = [0u8; 65];
    let decoded_len = len.div_ceil(2);
    if len % 2 == 1 {
        let mut tmp = [0u8; 131];
        tmp[0] = b'0';
        tmp[1..][..len].copy_from_slice(raw.as_bytes());
        hex::decode_to_slice(&tmp[..=len], &mut buf[..decoded_len])?;
    } else {
        hex::decode_to_slice(raw, &mut buf[..decoded_len])?;
    }
    match buf.first() {
        Some(0x02 | 0x03) if decoded_len == 33 => PublicKey::from_sec1_bytes(&buf[..33])
            .map_err(|e| CryptoError::PubkeyParse(e.to_string()).into()),
        Some(0x04) if decoded_len == 65 => PublicKey::from_sec1_bytes(&buf[..65])
            .map_err(|e| CryptoError::PubkeyParse(e.to_string()).into()),
        _ => Err(CryptoError::InvalidPubkeyEncoding("use 02, 03, or 04 prefix".to_string()).into()),
    }
}

/// Parse a signed decimal or hex string into `i128`.
///
/// Supports `0x` prefix for hex, optional `+`/`-` signs.
///
/// # Errors
///
/// Returns [`crate::error::RangeError::I128Overflow`] if the magnitude exceeds
/// the `i128` range.
pub fn parse_int(s: &str) -> Result<i128> {
    let s = s.trim();
    let (neg, body) = match s.strip_prefix('-').or_else(|| s.strip_prefix('+')) {
        Some(r) => (s.starts_with('-'), r),
        None => (false, s),
    };

    let mag: u128 = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).map_err(|_| RangeError::I128Overflow)?
    } else {
        body.parse::<u128>().map_err(|_| RangeError::I128Overflow)?
    };

    if neg {
        if mag > 1u128 << 127 {
            Err(RangeError::I128Overflow.into())
        } else if mag == 1u128 << 127 {
            Ok(i128::MIN)
        } else {
            Ok(-(mag as i128))
        }
    } else {
        i128::try_from(mag).map_err(|_| RangeError::I128Overflow.into())
    }
}

/// Format a `Scalar` as a minimal-width lowercase hex string.
#[must_use]
pub fn scalar_hex(s: &Scalar) -> String {
    let bytes = s.to_bytes();
    bytes
        .iter()
        .position(|b| *b != 0)
        .map_or_else(|| "0".into(), |i| hex::encode(&bytes[i..]))
}

/// Encode an affine point as a 33-byte compressed SEC1 key for hashing.
#[inline]
#[must_use]
pub fn affine_key(affine: &AffinePoint) -> [u8; 33] {
    use k256::elliptic_curve::point::AffineCoordinates;
    let x = affine.x();
    let x_bytes = x.as_ref();
    let prefix = if affine.y_is_odd().into() { 0x03 } else { 0x02 };
    let mut key = [0u8; 33];
    key[0] = prefix;
    key[1..].copy_from_slice(x_bytes);
    key
}

/// Encode the first 16 bytes of a compressed affine point as a `u128` key.
///
/// Collision probability for a table with `m` entries is `m² / 2¹²⁹`, which is
/// negligible for all supported ranges.  Any collision is caught by the
/// cryptographic verification step, so this is safe.
#[inline]
#[must_use]
pub fn affine_key_prefix(affine: &AffinePoint) -> u128 {
    use k256::elliptic_curve::point::AffineCoordinates;
    let x = affine.x();
    let x_bytes: &[u8] = x.as_ref();
    let prefix = if affine.y_is_odd().into() { 0x03u8 } else { 0x02u8 };
    let mut buf = [0u8; 16];
    buf[0] = prefix;
    buf[1..16].copy_from_slice(&x_bytes[..15]);
    u128::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint;
    use proptest::prelude::*;

    #[test]
    fn test_precompute_and_private_key() {
        let sig = crate::domain::Signature::new(
            Scalar::from(1u64),
            Scalar::from(3u64),
            Scalar::from(5u64),
        );
        let (a, b) = derive_affine_constants(&sig).unwrap();
        // d = alpha * 0 - beta = -beta
        assert_eq!(derive_private_key(0, a, b), Scalar::ZERO - b);
    }

    #[test]
    fn test_pubkey_conversion() {
        let pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk = parse_pubkey(pk_hex).unwrap();
        assert_eq!(hex::encode(pk.to_encoded_point(true).as_bytes()), pk_hex);
    }

    #[test]
    fn test_hex_parsing() {
        assert_eq!(parse_scalar("0xFF").unwrap(), parse_scalar("FF").unwrap());
        assert_eq!(
            parse_scalar("0xFFF").unwrap(),
            parse_scalar("0x0FFF").unwrap()
        );
    }

    #[test]
    fn test_range_parsing() {
        assert_eq!(parse_int("0").unwrap(), 0);
        assert_eq!(parse_int("100").unwrap(), 100);
        assert_eq!(parse_int("0xFF").unwrap(), 255);
        assert_eq!(parse_int("-0xFF").unwrap(), -255);
        assert_eq!(parse_int("+100").unwrap(), 100);
        assert_eq!(parse_int("+0xFF").unwrap(), 255);
    }

    #[test]
    fn test_pubkey_invalid() {
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("0xgg").is_err());
        assert!(parse_pubkey("01").is_err());
        assert!(parse_pubkey(&("02".to_string() + &"ff".repeat(31))).is_err());
        assert!(
            parse_pubkey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .is_ok()
        );
        let uncompressed = concat!(
            "04",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert!(parse_pubkey(uncompressed).is_ok());
    }

    #[test]
    fn test_edge_cases() {
        let sig = crate::domain::Signature::new(
            Scalar::from(1u64),
            Scalar::from(1u64),
            Scalar::from(0u64),
        );
        assert!(derive_affine_constants(&sig).is_ok());
    }

    #[test]
    fn test_parse_scalar_empty() {
        assert!(parse_scalar("").is_err());
        assert!(parse_scalar("  ").is_err());
        assert!(parse_scalar("0x").is_err());
    }

    #[test]
    fn test_parse_scalar_oversized() {
        let oversized = "0x".to_string() + &"ff".repeat(33);
        assert!(parse_scalar(&oversized).is_err());
    }

    #[test]
    fn test_parse_pubkey_oversized() {
        let oversized = "0x".to_string() + &"ff".repeat(66);
        assert!(parse_pubkey(&oversized).is_err());
    }

    #[test]
    fn test_parse_int_overflow() {
        let too_big = "-170141183460469231731687303715884105729";
        assert!(parse_int(too_big).is_err());
    }

    #[test]
    fn test_parse_int_min() {
        let min = "-170141183460469231731687303715884105728";
        assert_eq!(parse_int(min).unwrap(), i128::MIN);
    }

    use crate::fixtures::{r_from_nonce, sig_s};

    #[test]
    fn test_verify_ecdsa_valid() {
        let d = Scalar::from(0x3039u64);
        let nonce = 0x1234u64;
        let z = Scalar::from(1u64);
        let r = r_from_nonce(nonce);
        let s = sig_s(1, r, d, nonce);
        let pk = PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * d)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        assert!(verify_ecdsa_signature(&pk, &r, &s, &z).is_ok());
    }

    #[test]
    fn test_verify_ecdsa_invalid_s() {
        let d = Scalar::from(0x3039u64);
        let nonce = 0x1234u64;
        let z = Scalar::from(1u64);
        let r = r_from_nonce(nonce);
        let pk = PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * d)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        // s = 0 is never valid
        assert!(verify_ecdsa_signature(&pk, &r, &Scalar::ZERO, &z).is_err());
    }

    #[test]
    fn test_verify_ecdsa_wrong_pubkey() {
        let d = Scalar::from(0x3039u64);
        let wrong_d = Scalar::from(0x1234u64);
        let nonce = 0x1234u64;
        let z = Scalar::from(1u64);
        let r = r_from_nonce(nonce);
        let s = sig_s(1, r, d, nonce);
        let wrong_pk = PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * wrong_d)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        assert!(verify_ecdsa_signature(&wrong_pk, &r, &s, &z).is_err());
    }

    #[test]
    fn test_user_provided_values() {
        let r = parse_scalar("0xae3a7f6f10f9dd783818bb9ea7d9e1f3282d2cd73c7e71acef7c7bdf19f83be1").unwrap();
        let s = parse_scalar("0xd4e0c39ac4a4cfb655cf51af2b8e4a0e80ac7004515ea2249b9e2a2c7e5737e0").unwrap();
        let z = parse_scalar("0xd57586b5c9c6e51ff7689c7d75768106d4f3bba71bd850c3e30a91d46d386d8d").unwrap();
        let sig = crate::domain::Signature::new(r, s, z);
        let (alpha, beta) = derive_affine_constants(&sig).unwrap();

        let r_inv = r.invert().unwrap();
        let expected_alpha = r_inv * s;
        let expected_beta = r_inv * z;

        assert_eq!(alpha, expected_alpha);
        assert_eq!(beta, expected_beta);
    }

    proptest! {
        #[test]
        fn prop_parse_int_roundtrip(n in any::<i128>()) {
            let s = format!("{n}");
            let parsed = parse_int(&s).unwrap();
            prop_assert_eq!(parsed, n);
        }

        #[test]
        fn prop_derive_private_key_identity(alpha in any::<u64>().prop_map(Scalar::from), beta in any::<u64>().prop_map(Scalar::from)) {
            // d = alpha * 0 - beta = -beta
            prop_assert_eq!(derive_private_key(0, alpha, beta), Scalar::ZERO - beta);
        }

        #[test]
        fn prop_derive_affine_constants_roundtrip(
            r in any::<u64>().prop_filter("r must be non-zero", |s| *s != 0),
            s in any::<u64>(),
            z in any::<u64>(),
            k in any::<u64>(),
        ) {
            let r_scalar = Scalar::from(r);
            let s_scalar = Scalar::from(s);
            let z_scalar = Scalar::from(z);
            let sig = crate::domain::Signature::new(r_scalar, s_scalar, z_scalar);
            let (alpha, beta) = derive_affine_constants(&sig).unwrap();
            let _d = derive_private_key(k as u128, alpha, beta);
        }
    }
}
