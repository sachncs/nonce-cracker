//! Integration tests for nonce-cracker CLI
//!
//! These tests validate the command-line interface behavior including:
//! - Help output generation
//! - Command routing
//! - Argument validation
//! - Error handling

use assert_cmd::Command;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, Scalar,
};
use num_bigint::{BigInt, Sign};
use num_traits::Signed;
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

/// Tests that `--help` flag displays help and lists all commands.
///
/// # Expected Behavior
///
/// - Exit code 0
/// - Output contains program name "nonce-cracker"
/// - Output lists all subcommands: run, recover, example
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
    assert!(stdout.contains("recover"));
    assert!(stdout.contains("example"));
}

/// Tests that `example` command executes successfully.
///
/// # Expected Behavior
///
/// - Exit code 0
/// - Demo runs with predefined test values and recovers a private key
#[test]
fn test_example_command() {
    let log_dir = temp_log_dir("nonce_cracker_example");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    // Example should complete successfully (recovers d = 0x3039 in the demo case)
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

/// Tests that `run` command fails without required arguments.
///
/// # Expected Behavior
///
/// - Exit code non-zero (clap returns error)
/// - Missing required arguments detected
#[test]
fn test_run_requires_arguments() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args(["run"])
        .output()
        .expect("Failed to execute command");

    // Should fail due to missing required arguments
    assert!(!output.status.success());
}

/// Tests that `recover` command fails without required arguments.
///
/// # Expected Behavior
///
/// - Exit code non-zero (clap returns error)
/// - Missing required arguments detected
#[test]
fn test_recover_requires_arguments() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args(["recover"])
        .output()
        .expect("Failed to execute command");

    // Should fail due to missing required arguments
    assert!(!output.status.success());
}

/// Tests that invalid public key format is rejected.
///
/// # Expected Behavior
///
/// - Exit code non-zero
/// - Error message indicates pubkey parse failure
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

    // Should fail due to invalid pubkey
    assert!(!output.status.success());
}

/// Tests that recover command validates public key format.
///
/// # Expected Behavior
///
/// - Exit code non-zero
/// - Error message indicates pubkey parse failure
#[test]
fn test_recover_invalid_pubkey() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args([
            "recover", "--r1", "0x1", "--s1", "0x3", "--z1", "0x5", "--r2", "0x2", "--s2", "0x4",
            "--z2", "0x6", "--pubkey", "invalid", "--start", "0", "--end", "1000",
        ])
        .output()
        .expect("Failed to execute command");

    // Should fail due to invalid pubkey
    assert!(!output.status.success());
}

/// Tests that end < start range is rejected.
///
/// # Expected Behavior
///
/// - Exit code non-zero
/// - Error message indicates range validation failure
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

    // Should fail due to invalid range
    assert!(!output.status.success());
}

/// Tests that `recover` command with valid test data finds the private key.
#[test]
fn test_recover_with_valid_data() {
    let log_dir = temp_log_dir("nonce_cracker_recover");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args([
            "recover",
            "--r1",
            "0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba",
            "--s1",
            "0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8",
            "--z1",
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "--r2",
            "0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12",
            "--s2",
            "0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7",
            "--z2",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "--pubkey",
            "03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f",
            "--start",
            "0",
            "--end",
            "10",
            "--outfile",
            "recover_valid.log",
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

    let report = std::fs::read_to_string(log_dir.join("recover_valid.log"))
        .expect("recover report should be written");
    assert!(report.contains("FOUND delta=1"));
}

/// Tests that `run` command with valid test data finds the private key.
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

/// Tests that the binary accepts a signed delta window and writes the expected result.
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
    // Keep the fixture deterministic so the CLI test exercises the exact same
    // additive nonce relation as the unit-level derivation tests.
    let private_key = Scalar::from(0x3039u64);
    let nonce = 0x1234u64;
    let next_nonce = nonce
        .checked_sub(1)
        .expect("fixture delta must stay positive");
    let curve_order = secp256k1_curve_order();

    let r1 = r_value_from_nonce(nonce, &curve_order);
    let r2 = r_value_from_nonce(next_nonce, &curve_order);
    let r1_scalar = bigint_to_scalar(&r1);
    let r2_scalar = bigint_to_scalar(&r2);

    let s1 = signature_s_value(1u64, r1_scalar, private_key, nonce);
    let s2 = signature_s_value(2u64, r2_scalar, private_key, next_nonce);
    let pubkey = ProjectivePoint::GENERATOR * private_key;

    NegativeDeltaFixture {
        r1: bigint_to_hex(&r1),
        r2: bigint_to_hex(&r2),
        s1: bigint_to_hex(&s1),
        s2: bigint_to_hex(&s2),
        pubkey: hex::encode(pubkey.to_affine().to_encoded_point(true).as_bytes()),
    }
}

fn signature_s_value(message_hash: u64, r: Scalar, private_key: Scalar, nonce: u64) -> BigInt {
    let s = (Scalar::from(message_hash) + r * private_key)
        * Scalar::from(nonce)
            .invert()
            .expect("nonce must be invertible in the scalar field");
    BigInt::from_bytes_be(Sign::Plus, &s.to_bytes())
}

fn bigint_to_scalar(value: &BigInt) -> Scalar {
    let (_, bytes) = value.to_bytes_be();
    let mut wide = [0u8; 32];
    wide[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_repr(wide.into()).expect("fixture value must fit in a scalar")
}

fn bigint_to_hex(value: &BigInt) -> String {
    let (_, bytes) = value.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

fn r_value_from_nonce(nonce: u64, curve_order: &BigInt) -> BigInt {
    let point = ProjectivePoint::GENERATOR * Scalar::from(nonce);
    let encoded = point.to_affine().to_encoded_point(true);
    let x = BigInt::from_bytes_be(Sign::Plus, &encoded.as_bytes()[1..33]);
    let remainder = &x % curve_order;
    if remainder.is_negative() {
        remainder + curve_order
    } else {
        remainder
    }
}

fn secp256k1_curve_order() -> BigInt {
    BigInt::parse_bytes(
        b"115792089237316195423570985008687907852837564279074904382605163141518161494337",
        10,
    )
    .expect("valid curve order")
}
