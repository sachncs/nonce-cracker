use crate::{Error, Result};
use hex::FromHex;
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
/// Returns an error if `s1` or the denominator `a` is not invertible.
pub fn derive_affine_constants(
    r1: Scalar,
    r2: Scalar,
    s1: Scalar,
    s2: Scalar,
    z1: Scalar,
    z2: Scalar,
) -> Result<(Scalar, Scalar)> {
    let u: Scalar = Option::from(s1.invert()).ok_or_else(|| Error("s1 not invertible".into()))?;
    let a: Scalar = s2 * r1 * u - r2;
    let b: Scalar = z2 - s2 * z1 * u;
    let c: Scalar = s2;
    let a_inv: Scalar =
        Option::from(a.invert()).ok_or_else(|| Error("denominator not invertible".into()))?;
    Ok((-(c * a_inv), b * a_inv))
}

/// Compute the candidate private key for a given `delta` using the affine
/// relation `d = alpha * delta + beta`.
#[inline]
pub fn derive_private_key(delta: i64, alpha: Scalar, beta: Scalar) -> Scalar {
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
pub fn parse_scalar(s: &str) -> Result<Scalar> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Err(Error("empty hex string".into()));
    }
    let padded = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = Vec::from_hex(&padded)?;
    if bytes.len() > 32 {
        return Err(Error("scalar exceeds 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    Option::from(Scalar::from_repr(arr.into())).ok_or_else(|| Error("scalar out of range".into()))
}

/// Parse a hex string into a secp256k1 `PublicKey`.
///
/// Accepts compressed (`02`/`03` + 32-byte x) or uncompressed
/// (`04` + 32-byte x + 32-byte y) SEC1 encoding.
pub fn parse_pubkey(s: &str) -> Result<PublicKey> {
    let bytes = Vec::from_hex(s.trim().trim_start_matches("0x").trim_start_matches("0X"))?;
    match bytes.first() {
        Some(0x02 | 0x03) if bytes.len() == 33 => {
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error(format!("pubkey: {e}")))
        }
        Some(0x04) if bytes.len() == 65 => {
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error(format!("pubkey: {e}")))
        }
        _ => Err(Error("pubkey: use 02, 03, or 04 prefix".into())),
    }
}

/// Parse a signed decimal or hex string into `i64`.
///
/// Supports `0x` prefix for hex, optional `+`/`-` signs.
pub fn parse_int(s: &str) -> Result<i64> {
    let s = s.trim();
    let (neg, body) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };

    let mag = if body.starts_with("0x") || body.starts_with("0X") {
        u128::from_str_radix(&body[2..], 16).map_err(|e| Error(format!("parse error: {e}")))?
    } else {
        body.parse::<u128>()
            .map_err(|e| Error(format!("parse error: {e}")))?
    };

    if neg {
        let limit = u128::try_from(i64::MAX).expect("i64::MAX fits in u128") + 1;
        if mag > limit {
            return Err(Error("value overflows i64".into()));
        }
        let signed = -(i128::try_from(mag).map_err(|_| Error("value overflows i64".into()))?);
        i64::try_from(signed).map_err(|_| Error("value overflows i64".into()))
    } else {
        i64::try_from(mag).map_err(|_| Error("value overflows i64".into()))
    }
}

/// Format a `Scalar` as a minimal-width lowercase hex string.
pub fn scalar_hex(s: &Scalar) -> String {
    let bytes = s.to_bytes();
    match bytes.iter().position(|b| *b != 0) {
        None => "0".into(),
        Some(i) => hex::encode(&bytes[i..]),
    }
}

/// Encode an affine point as a 33-byte compressed SEC1 key for hashing.
#[inline]
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
        let (a, b) = derive_affine_constants(
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
            Scalar::from(5u64),
            Scalar::from(6u64),
        )
        .unwrap();
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
        assert!(derive_affine_constants(
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(1u64),
            Scalar::from(1u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
        )
        .is_ok());
    }
}
