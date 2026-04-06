//! Integration tests for nonce-cracker CLI
//!
//! These tests validate the command-line interface behavior including:
//! - Help output generation
//! - Command routing
//! - Argument validation
//! - Error handling

use assert_cmd::Command;

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

    assert!(output.status.success());
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
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
        .args(["example"])
        .output()
        .expect("Failed to execute command");

    // Example should complete successfully (recovers d = 0x3039 in the demo case)
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FOUND"));
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
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
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
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FOUND"));
}

/// Tests that `run` command with valid test data finds the private key.
#[test]
fn test_run_with_valid_data() {
    let output = Command::cargo_bin("nonce-cracker")
        .expect("Binary should be built")
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
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FOUND"));
}
