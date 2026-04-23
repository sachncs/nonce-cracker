use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar,
};

fn main() {
    let d = 0x3039u64;
    let d_scalar = Scalar::from(d);

    let delta = 1u64;
    let k = 0x1234u64;
    let k_scalar = Scalar::from(k);
    let k_prime = k + delta;
    let k_prime_scalar = Scalar::from(k_prime);

    let r1_point = ProjectivePoint::GENERATOR * k_scalar;
    let r1_enc = r1_point.to_affine().to_encoded_point(true);
    let mut r1_arr = [0u8; 32];
    r1_arr.copy_from_slice(&r1_enc.as_bytes()[1..33]);
    let r1_scalar = Scalar::from_repr(r1_arr.into()).unwrap();

    let r2_point = ProjectivePoint::GENERATOR * k_prime_scalar;
    let r2_enc = r2_point.to_affine().to_encoded_point(true);
    let mut r2_arr = [0u8; 32];
    r2_arr.copy_from_slice(&r2_enc.as_bytes()[1..33]);
    let r2_scalar = Scalar::from_repr(r2_arr.into()).unwrap();

    let z1_scalar = Scalar::from(1u64);
    let z2_scalar = Scalar::from(2u64);

    let s1_scalar = (z1_scalar + r1_scalar * d_scalar) * k_scalar.invert().unwrap();
    let s2_scalar = (z2_scalar + r2_scalar * d_scalar) * k_prime_scalar.invert().unwrap();

    let u = s1_scalar.invert().unwrap();
    let a = s2_scalar * r1_scalar * u - r2_scalar;
    let b = z2_scalar - s2_scalar * z1_scalar * u;
    let c = s2_scalar;
    let a_inv = a.invert().unwrap();
    let alpha = -(c * a_inv);
    let beta = b * a_inv;

    let computed_d = alpha * Scalar::from(delta) + beta;

    let pk_point = ProjectivePoint::GENERATOR * d_scalar;
    let pk_enc = pk_point.to_affine().to_encoded_point(true);
    let pk_hex = hex::encode(pk_enc.as_bytes());

    println!("// Generated test data for nonce-cracker");
    println!("// Private key d = 0x{d:x}");
    println!("// k = 0x{k:x}, k' = k + {delta} = 0x{k_prime:x}");
    println!();
    println!("// Signature 1 (k = 0x{k:x}, z1 = 1):");
    println!("let r1 = 0x{};", hex::encode(r1_arr));
    println!("let s1 = 0x{};", hex::encode(s1_scalar.to_bytes()));
    println!("let z1 = 0x0000000000000000000000000000000000000000000000000000000000000001;");
    println!();
    println!("// Signature 2 (k' = 0x{k_prime:x}, z2 = 2):");
    println!("let r2 = 0x{};", hex::encode(r2_arr));
    println!("let s2 = 0x{};", hex::encode(s2_scalar.to_bytes()));
    println!("let z2 = 0x0000000000000000000000000000000000000000000000000000000000000002;");
    println!();
    println!("let pubkey = \"{pk_hex}\";");
    println!();
    println!("// Precomputed values:");
    println!("// alpha = 0x{}", hex::encode(alpha.to_bytes()));
    println!("// beta = 0x{}", hex::encode(beta.to_bytes()));
    println!("// delta = {delta}");
    println!();

    if computed_d == d_scalar {
        println!("// SUCCESS: d matches expected value 0x{d:x}");
    } else {
        println!("// NOTE: computed d != expected d = 0x{d:x}");
    }

    println!("\n// === Rust code for src/main.rs ===");
    println!("let r1 = parse_scalar_hex(\"0x{}\")?;", hex::encode(r1_arr));
    println!(
        "let s1 = parse_scalar_hex(\"0x{}\")?;",
        hex::encode(s1_scalar.to_bytes())
    );
    println!("let z1 = parse_scalar_hex(\"0x0000000000000000000000000000000000000000000000000000000000000001\")?;");
    println!("let r2 = parse_scalar_hex(\"0x{}\")?;", hex::encode(r2_arr));
    println!(
        "let s2 = parse_scalar_hex(\"0x{}\")?;",
        hex::encode(s2_scalar.to_bytes())
    );
    println!("let z2 = parse_scalar_hex(\"0x0000000000000000000000000000000000000000000000000000000000000002\")?;");
    println!("let pk = parse_public_key(\"{pk_hex}\")?;");
    println!(
        "search(r1, r2, s1, s2, z1, z2, pk, 0, {}, 1, None, false, \"example.log\")?",
        delta + 1
    );
}
