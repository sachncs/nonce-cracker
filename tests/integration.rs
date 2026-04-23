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
