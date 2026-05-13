//! End-to-end CLI integration tests.
//!
//! Covers the `example` and `run` subcommands, argument validation,
//! logging behaviour, and dry-run cryptographic correctness checks.

use assert_cmd::Command;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, PublicKey, Scalar,
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

fn single_sig_fixture() -> (String, String, String, String) {
    let d = Scalar::from(0x3039u64);
    let nonce = 0x1234u64;
    let z = Scalar::from(1u64);

    let r = {
        let enc = (ProjectivePoint::GENERATOR * Scalar::from(nonce))
            .to_affine()
            .to_encoded_point(true);
        let mut b = [0u8; 32];
        b.copy_from_slice(&enc.as_bytes()[1..33]);
        Scalar::from_repr(b.into()).unwrap()
    };
    let s = (Scalar::from(1u64) + r * d) * Scalar::from(nonce).invert().unwrap();

    let pk = PublicKey::from_sec1_bytes(
        (ProjectivePoint::GENERATOR * d)
            .to_affine()
            .to_encoded_point(true)
            .as_bytes(),
    )
    .unwrap();

    let scalar_to_hex = |s: &Scalar| format!("0x{}", hex::encode(s.to_bytes()));

    (
        scalar_to_hex(&r),
        scalar_to_hex(&s),
        scalar_to_hex(&z),
        hex::encode(pk.to_encoded_point(true).as_bytes()),
    )
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
    assert!(report.contains("FOUND nonce=4660"));
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
    let (r, s, z, _pk) = single_sig_fixture();
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args([
            "run", "--r", &r, "--s", &s, "--z", &z, "--pubkey", "invalid", "--start", "0", "--end",
            "1000",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
fn test_invalid_range() {
    let (r, s, z, pk) = single_sig_fixture();
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args([
            "run", "--r", &r, "--s", &s, "--z", &z, "--pubkey", &pk, "--start", "1000", "--end",
            "0",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
}

#[test]
fn test_run_with_valid_data() {
    let (r, s, z, pk) = single_sig_fixture();
    let log_dir = temp_log_dir("nonce_cracker_run");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .args([
            "run",
            "--r",
            &r,
            "--s",
            &s,
            "--z",
            &z,
            "--pubkey",
            &pk,
            "--start",
            "0",
            "--end",
            "10000",
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
    assert!(report.contains("FOUND nonce=4660"));
}

#[test]
fn test_invalid_max_threads() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_MAX_THREADS", "0")
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("config"));
    assert!(stderr.contains("NONCE_CRACKER_MAX_THREADS"));
}

#[test]
fn test_invalid_log_level() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_LEVEL", "invalid")
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("logging"));
    assert!(stderr.contains("invalid"));
}

#[test]
fn test_no_console_logging() {
    let log_dir = temp_log_dir("nonce_cracker_no_console");
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .env("NONCE_CRACKER_LOG_DIR", &log_dir)
        .env("NONCE_CRACKER_LOG_CONSOLE", "false")
        .env("NONCE_CRACKER_LOG_LEVEL", "debug")
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // tracing logs should not appear on stdout when console is disabled
    assert!(!stdout.contains("logging initialized"));

    let app_log = std::fs::read_to_string(log_dir.join("nonce-cracker.log"))
        .expect("application log should be written");
    assert!(app_log.contains("logging initialized"));
    assert!(app_log.contains("event=search_result"));
}
