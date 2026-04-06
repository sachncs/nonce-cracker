//! # nonce-cracker Examples
//!
//! This directory contains examples demonstrating usage.
//!
//! ## Running Examples
//!
//! ```bash
//! # Run the demonstration (recovers a known private key)
//! cargo run -- example
//!
//! # Generate test data for the tool
//! cargo run --example generate
//! ```
//!
//! ## Demonstration
//!
//! The `example` command runs a self-contained demonstration that:
//! - Uses generated test data with a known private key (d = 0x3039)
//! - Searches range 0..=2 (delta = 1 is within range)
//! - Verifiably recovers the private key
//!
//! ## Generating Test Data
//!
//! Use `cargo run --example generate` to create new test data.
//! The generator produces valid ECDSA signatures with an affine nonce
//! relation, ensuring the tool can recover the private key.

/// Demonstrates the `nonce-cracker recover` command with test signature values.
///
/// This example shows how to use the recover command to search for a private key
/// given two ECDSA signatures that share a nonce.
///
/// ## Test Data
///
/// The example uses generated test data where:
/// - Private key d = 0x3039
/// - Nonce relation: k' = k + 1
/// - Search delta = 1
///
/// ## Expected Output
///
/// ```
/// FOUND delta=0x1 d=0x... (written to example.log)
/// ```
///
/// ## Notes
///
/// - Range is limited (0 to 2) for fast demonstration
/// - The tool finds delta = 1 and recovers d = 0x3039
/// - Thread count set to 4 for consistent behavior
fn main() {
    println!("nonce-cracker Examples");
    println!("======================");
    println!();
    println!("This binary demonstrates usage patterns.");
    println!();
    println!("To run the actual tool, use:");
    println!("  cargo run -- example    # Run the built-in demonstration");
    println!("  cargo run -- recover   # Use the recover command");
    println!("  cargo run -- run       # Use the run command");
    println!();
    println!("See README.md for complete documentation.");
}
