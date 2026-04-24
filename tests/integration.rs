use assert_cmd::Command;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar,
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_log_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), nanos));
    std::fs::create_dir_all(&path).expect("temporary log directory should be creatable");
    path
}

#[test]
fn test_help_flag() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args(["--help"])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonce-cracker"));
    assert!(stdout.contains("run"));
    assert!(stdout.contains("example"));
}

#[test]
fn test_example_command() {
    let log_dir = temp_log_dir("nonce_cracker_example");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=found"));

    let report = std::fs::read_to_string(log_dir.join("example.log"))
        .expect("example report should be written");
    assert!(report.contains("FOUND delta=1"));
    let app_log = std::fs::read_to_string(log_dir.join("nonce-cracker.log"))
        .expect("application log should be written");
    assert!(app_log.contains("event=search_result"));
}

#[test]
fn test_run_requires_arguments() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args(["run"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
fn test_invalid_pubkey() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args([
            "run", "--r1", "0x1", "--r2", "0x2", "--s1", "0x3", "--s2", "0x4", "--z1", "0x5",
            "--z2", "0x6", "--pubkey", "invalid", "--start", "0", "--end", "1000",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
fn test_invalid_range() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args([
            "run", "--r1", "0x1", "--r2", "0x2", "--s1", "0x3", "--s2", "0x4", "--z1", "0x5",
            "--z2", "0x6", "--pubkey", "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "--start", "1000", "--end", "0",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
fn test_run_with_valid_data() {
    let log_dir = temp_log_dir("nonce_cracker_run");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args([
            "run",
            "--r1",
            "0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba",
            "--r2",
            "0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12",
            "--s1",
            "0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8",
            "--s2",
            "0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7",
            "--z1",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "--z2",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "--pubkey",
            "03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f",
            "--start",
            "0",
            "--end",
            "10",
            "--outfile",
            "run_valid.log",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=found"));

    let report = std::fs::read_to_string(log_dir.join("run_valid.log"))
        .expect("run report should be written");
    assert!(report.contains("FOUND delta=1"));
}

#[test]
fn test_run_with_negative_delta_window() {
    let log_dir = temp_log_dir("nonce_cracker_negative_delta");
    let outfile = "negative_delta.log";
    let fixture = negative_delta_fixture();

    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args([
            "run",
            "--r1",
            &fixture.r1,
            "--r2",
            &fixture.r2,
            "--s1",
            &fixture.s1,
            "--s2",
            &fixture.s2,
            "--z1",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "--z2",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "--pubkey",
            &fixture.pubkey,
            "--start",
            "-2",
            "--end",
            "0",
            "--outfile",
            outfile,
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=found"));

    let log = std::fs::read_to_string(log_dir.join(outfile)).expect("log file should be written");
    assert!(log.contains("FOUND delta=-1"));
    let app_log = std::fs::read_to_string(log_dir.join("nonce-cracker.log"))
        .expect("application log should be written");
    assert!(app_log.contains("event=search_result"));
}

struct NegativeDeltaFixture {
    r1: String,
    r2: String,
    s1: String,
    s2: String,
    pubkey: String,
}

fn negative_delta_fixture() -> NegativeDeltaFixture {
    let d = Scalar::from(0x3039u64);
    let nonce = 0x1234u64;
    let next_nonce = nonce - 1;

    let r1 = r_value_from_nonce(nonce);
    let r2 = r_value_from_nonce(next_nonce);

    let s1 = signature_s_value(1, r1, d, nonce);
    let s2 = signature_s_value(2, r2, d, next_nonce);
    let pubkey = ProjectivePoint::GENERATOR * d;

    NegativeDeltaFixture {
        r1: scalar_to_hex(&r1),
        r2: scalar_to_hex(&r2),
        s1: scalar_to_hex(&s1),
        s2: scalar_to_hex(&s2),
        pubkey: hex::encode(pubkey.to_affine().to_encoded_point(true).as_bytes()),
    }
}

fn signature_s_value(z: u64, r: Scalar, d: Scalar, nonce: u64) -> Scalar {
    (Scalar::from(z) + r * d) * Scalar::from(nonce).invert().unwrap()
}

fn r_value_from_nonce(nonce: u64) -> Scalar {
    let point = ProjectivePoint::GENERATOR * Scalar::from(nonce);
    let encoded = point.to_affine().to_encoded_point(true);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&encoded.as_bytes()[1..33]);
    Scalar::from_repr(bytes.into()).unwrap()
}

fn scalar_to_hex(s: &Scalar) -> String {
    format!("0x{}", hex::encode(s.to_bytes()))
}

#[test]
fn test_batch_normalize_alpha_hex() {
    use k256::elliptic_curve::BatchNormalize;

    let alpha_bytes =
        hex::decode("1a574f1861113593a50c7872b9a39d14251becd78cb2d5656588ff49aeb862e2").unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&alpha_bytes);
    let alpha = Scalar::from_repr(arr.into()).unwrap();
    let step_point = ProjectivePoint::GENERATOR * alpha;

    println!(
        "alpha from hex, step_point is identity: {}",
        step_point == ProjectivePoint::IDENTITY
    );
    let pair = vec![ProjectivePoint::IDENTITY, step_point];
    println!("Testing [IDENTITY, step_point from hex alpha]...");
    let _affines = ProjectivePoint::batch_normalize(pair.as_slice());
    println!("OK");
}

#[test]
fn test_alpha_comparison() {
    use nonce_cracker::crypto::{derive_affine_constants, parse_scalar};

    let r1 =
        parse_scalar("0x59b220002f5dc107d18dd0152d7936f99368d85951b0234a7060847f6057e584").unwrap();
    let s1 =
        parse_scalar("0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b").unwrap();
    let z1 =
        parse_scalar("0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e").unwrap();
    let r2 =
        parse_scalar("0x9b6debb986dbb835943987c859a3e81e93438393a367b58d8d539dba872fa954").unwrap();
    let s2 =
        parse_scalar("0x7999704e31ccda0c3c6f2f34e028bbcbd1de65de33d02142eb241768bb5e8fea").unwrap();
    let z2 =
        parse_scalar("0x7b2e9d83f2a851266582e49c88d0d5dc28638dd7b9b8b9cf4d77d60c16bfc7d5").unwrap();

    let (alpha_derived, _) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();

    let alpha_bytes =
        hex::decode("1a574f1861113593a50c7872b9a39d14251becd78cb2d5656588ff49aeb862e2").unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&alpha_bytes);
    let alpha_hex = Scalar::from_repr(arr.into()).unwrap();

    println!(
        "alpha_derived bytes: {}",
        hex::encode(alpha_derived.to_bytes())
    );
    println!("alpha_hex bytes:     {}", hex::encode(alpha_hex.to_bytes()));
    println!("alphas equal: {}", alpha_derived == alpha_hex);

    let step_derived = ProjectivePoint::GENERATOR * alpha_derived;
    let step_hex = ProjectivePoint::GENERATOR * alpha_hex;

    println!("step_derived == step_hex: {}", step_derived == step_hex);

    use k256::elliptic_curve::BatchNormalize;
    let pair = vec![ProjectivePoint::IDENTITY, step_derived];
    let _affines = ProjectivePoint::batch_normalize(pair.as_slice());
    println!("step_derived batch OK");
}

#[test]
fn test_identity_plus_step() {
    use k256::elliptic_curve::BatchNormalize;
    use nonce_cracker::crypto::{derive_affine_constants, parse_scalar};

    let r1 =
        parse_scalar("0x59b220002f5dc107d18dd0152d7936f99368d85951b0234a7060847f6057e584").unwrap();
    let s1 =
        parse_scalar("0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b").unwrap();
    let z1 =
        parse_scalar("0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e").unwrap();
    let r2 =
        parse_scalar("0x9b6debb986dbb835943987c859a3e81e93438393a367b58d8d539dba872fa954").unwrap();
    let s2 =
        parse_scalar("0x7999704e31ccda0c3c6f2f34e028bbcbd1de65de33d02142eb241768bb5e8fea").unwrap();
    let z2 =
        parse_scalar("0x7b2e9d83f2a851266582e49c88d0d5dc28638dd7b9b8b9cf4d77d60c16bfc7d5").unwrap();

    let (alpha, _) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();
    let step_point = ProjectivePoint::GENERATOR * alpha;

    let identity_plus_step = ProjectivePoint::IDENTITY + step_point;
    println!(
        "identity_plus_step == step_point: {}",
        identity_plus_step == step_point
    );

    let pair = vec![ProjectivePoint::IDENTITY, identity_plus_step];
    println!("Testing [IDENTITY, IDENTITY + step_point]...");
    let _affines = ProjectivePoint::batch_normalize(pair.as_slice());
    println!("OK");
}

#[test]
fn test_dry_run_specific_values() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use nonce_cracker::crypto::{derive_affine_constants, parse_pubkey, parse_scalar, scalar_hex};

    let r1 =
        parse_scalar("0x59b220002f5dc107d18dd0152d7936f99368d85951b0234a7060847f6057e584").unwrap();
    let s1 =
        parse_scalar("0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b").unwrap();
    let z1 =
        parse_scalar("0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e").unwrap();
    let r2 =
        parse_scalar("0x9b6debb986dbb835943987c859a3e81e93438393a367b58d8d539dba872fa954").unwrap();
    let s2 =
        parse_scalar("0x7999704e31ccda0c3c6f2f34e028bbcbd1de65de33d02142eb241768bb5e8fea").unwrap();
    let z2 =
        parse_scalar("0x7b2e9d83f2a851266582e49c88d0d5dc28638dd7b9b8b9cf4d77d60c16bfc7d5").unwrap();
    let pk = parse_pubkey(
        "04f86dcd9551f0f21bcda9fdbe0aa00fc4ec61fdf57c35d5f115d012841867a9d8f97fc9f54553df1a1c2ca2ecac517206df75e3dd13f775e819b18572584972f5",
    )
    .unwrap();

    let (alpha, beta) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();

    println!("alpha: 0x{}", scalar_hex(&alpha));
    println!("beta:  0x{}", scalar_hex(&beta));

    let target = pk.as_affine().to_encoded_point(false).as_bytes().to_vec();

    for delta in [
        123_456_787i128,
        123_456_788,
        123_456_789,
        123_456_790,
        123_456_791,
    ] {
        let d = nonce_cracker::crypto::derive_private_key(delta, alpha, beta);
        let candidate = (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        println!("delta={} matches target: {}", delta, candidate == target);
    }
}

#[test]
fn test_dry_run_algebraic_delta() {
    use k256::elliptic_curve::PrimeField;
    use nonce_cracker::crypto::{derive_affine_constants, parse_scalar};

    let r1 =
        parse_scalar("0x59b220002f5dc107d18dd0152d7936f99368d85951b0234a7060847f6057e584").unwrap();
    let s1 =
        parse_scalar("0xa7fa8b4a2944338eee5180dbee8e763334c9c09c5f6450c8e08150714e3bd81b").unwrap();
    let z1 =
        parse_scalar("0x585e5a8c07383473109d225e68d210b5bc791f870357bf1c61fb5dbf6578740e").unwrap();
    let r2 =
        parse_scalar("0x9b6debb986dbb835943987c859a3e81e93438393a367b58d8d539dba872fa954").unwrap();
    let s2 =
        parse_scalar("0x7999704e31ccda0c3c6f2f34e028bbcbd1de65de33d02142eb241768bb5e8fea").unwrap();
    let z2 =
        parse_scalar("0x7b2e9d83f2a851266582e49c88d0d5dc28638dd7b9b8b9cf4d77d60c16bfc7d5").unwrap();

    let (alpha, beta) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();

    // k1 = (z1 + r1*d) / s1, k2 = (z2 + r2*d) / s2, d = alpha*delta + beta
    // k2 - k1 = delta  =>  solve for delta algebraically
    let s1_inv = s1.invert().unwrap();
    let s2_inv = s2.invert().unwrap();

    // A = alpha*(r2/s2 - r1/s1)
    let a_term = alpha * (r2 * s2_inv - r1 * s1_inv);

    // B = (z2 + r2*beta)/s2 - (z1 + r1*beta)/s1
    let b_term = (z2 + r2 * beta) * s2_inv - (z1 + r1 * beta) * s1_inv;

    println!("a_term: 0x{}", hex::encode(a_term.to_bytes()));
    println!("b_term: 0x{}", hex::encode(b_term.to_bytes()));

    // delta = -B / (A - 1)  =  -B * (A - 1)^{-1}
    let denom = a_term - Scalar::from(1u64);
    println!("denom:  0x{}", hex::encode(denom.to_bytes()));

    let denom_inv = denom.invert();
    if denom_inv.is_some().into() {
        let delta_scalar = -b_term * denom_inv.unwrap();
        println!("delta (scalar): 0x{}", hex::encode(delta_scalar.to_bytes()));

        // Convert delta_scalar to i64. Since Scalar wraps mod n, we need to check if it's < n/2.
        let delta_bytes = delta_scalar.to_bytes();
        println!("delta bytes: {:?}", delta_bytes);
    } else {
        println!("denom is not invertible!");
    }
}
