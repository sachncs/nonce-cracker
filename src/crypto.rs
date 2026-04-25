use crate::domain::SignaturePair;
use crate::error::{CryptoError, Result};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    AffinePoint, PublicKey, Scalar,
};

/// Derive the affine constants `alpha` and `beta` from two ECDSA signatures
/// under the assumption that the nonces are related by `k2 = k1 + delta`.
///
/// The private key can then be expressed as:
///   `d = alpha * delta + beta  (mod n)`
///
/// # Errors
///
/// Returns [`CryptoError::S1NotInvertible`] if `s1` has no inverse, or
/// [`CryptoError::DenominatorNotInvertible`] if the denominator `a` is zero.
pub fn derive_affine_constants(pair: &SignaturePair) -> Result<(Scalar, Scalar)> {
    let u: Scalar = Option::from(pair.first.s.invert()).ok_or(CryptoError::S1NotInvertible)?;
    let su = pair.second.s * u;
    let a: Scalar = su * pair.first.r - pair.second.r;
    let b: Scalar = pair.second.z - su * pair.first.z;
    let c: Scalar = pair.second.s;
    let a_inv: Scalar = Option::from(a.invert()).ok_or(CryptoError::DenominatorNotInvertible)?;
    Ok((-(c * a_inv), b * a_inv))
}

/// Compute the candidate private key for a given `delta` using the affine
/// relation `d = alpha * delta + beta`.
#[inline]
#[must_use]
pub fn derive_private_key(delta: i128, alpha: Scalar, beta: Scalar) -> Scalar {
    let s = Scalar::from(delta.unsigned_abs());
    if delta < 0 {
        beta - alpha * s
    } else {
        alpha * s + beta
    }
}

/// Parse a hex string into a secp256k1 `Scalar`.
///
/// Accepts with or without `0x` prefix. Odd-length hex is zero-padded.
/// Returns an error for empty strings, oversized values (>32 bytes), or
/// values outside the scalar field range.
///
/// # Errors
///
/// Returns [`CryptoError::EmptyHexString`], [`CryptoError::ScalarExceeds32Bytes`],
/// or [`CryptoError::ScalarOutOfRange`] for invalid input.
pub fn parse_scalar(s: &str) -> Result<Scalar> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Err(CryptoError::EmptyHexString.into());
    }
    let len = raw.len();
    if len > 64 {
        return Err(CryptoError::ScalarExceeds32Bytes.into());
    }
    let mut arr = [0u8; 32];
    let decoded_len = len.div_ceil(2);
    if len % 2 == 1 {
        let mut tmp = [0u8; 65];
        tmp[0] = b'0';
        tmp[1..][..len].copy_from_slice(raw.as_bytes());
        hex::decode_to_slice(&tmp[..=len], &mut arr[32 - decoded_len..])?;
    } else {
        hex::decode_to_slice(raw, &mut arr[32 - decoded_len..])?;
    }
    Option::from(Scalar::from_repr(arr.into())).ok_or_else(|| CryptoError::ScalarOutOfRange.into())
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

/// `i128::MIN` expressed as a `u128` magnitude.
const I128_MIN_MAG: u128 = 1_u128 << 127;

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
    let (neg, body) = s
        .strip_prefix('-')
        .map(|r| (true, r))
        .or_else(|| s.strip_prefix('+').map(|r| (false, r)))
        .unwrap_or((false, s));

    let mag = if body.starts_with("0x") || body.starts_with("0X") {
        u128::from_str_radix(&body[2..], 16).map_err(|_| crate::error::RangeError::I128Overflow)?
    } else {
        body.parse::<u128>()
            .map_err(|_| crate::error::RangeError::I128Overflow)?
    };

    if neg {
        if mag > I128_MIN_MAG {
            return Err(crate::error::RangeError::I128Overflow.into());
        }
        if mag == I128_MIN_MAG {
            Ok(i128::MIN)
        } else {
            Ok(-(i128::try_from(mag).map_err(|_| crate::error::RangeError::I128Overflow)?))
        }
    } else {
        i128::try_from(mag).map_err(|_| crate::error::RangeError::I128Overflow.into())
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
    let enc = affine.to_encoded_point(true);
    let bytes = enc.as_bytes();
    let mut key = [0u8; 33];
    key[..bytes.len()].copy_from_slice(bytes);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precompute_and_private_key() {
        let sig1 = SignaturePair::new(
            crate::domain::Signature::new(
                Scalar::from(1u64),
                Scalar::from(3u64),
                Scalar::from(5u64),
            ),
            crate::domain::Signature::new(
                Scalar::from(2u64),
                Scalar::from(4u64),
                Scalar::from(6u64),
            ),
        );
        let (a, b) = derive_affine_constants(&sig1).unwrap();
        assert_eq!(derive_private_key(0, a, b), b);
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
    fn test_signed_delta() {
        let a = Scalar::from(1u64);
        let b = Scalar::from(2u64);
        assert_eq!(derive_private_key(-1, a, b), b - a);
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
        let sig = SignaturePair::new(
            crate::domain::Signature::new(
                Scalar::from(1u64),
                Scalar::from(1u64),
                Scalar::from(0u64),
            ),
            crate::domain::Signature::new(
                Scalar::from(2u64),
                Scalar::from(1u64),
                Scalar::from(0u64),
            ),
        );
        assert!(derive_affine_constants(&sig).is_ok());
    }

    #[test]
    fn test_derive_private_key_i128_min() {
        let a = Scalar::from(1u64);
        let b = Scalar::from(2u64);
        let _ = derive_private_key(i128::MIN, a, b);
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
}
