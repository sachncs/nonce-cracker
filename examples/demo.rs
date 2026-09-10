//! # nonce-cracker Examples
//!
//! This example binary prints usage guidance for the crate's command-line interface.
//!
//! ## Running Examples
//!
//! ```bash
//! # Run the bundled demonstration command
//! cargo run -- example
//!
//! # Generate test data for the tool
//! cargo run --example generate
//!
//! # Run a search with signatures
//! cargo run -- run \
//!   --r1 0x... --r2 0x... --s1 0x... --s2 0x... \
//!   --z1 0x... --z2 0x... --pubkey 0x...
//! ```
//!
//! ## Bundled demonstration
//!
//! The `example` command runs the built-in search over generated test data.
//!
//! ## Generating Test Data
//!
//! Use `cargo run --example generate` to create new test data.
//! The generator produces valid ECDSA signatures with an affine nonce
//! relation, ensuring the tool can recover the private key.

/// Prints a short overview of the CLI entry points.
///
/// This example does not execute a search; it points users at the main binary
/// and the `example` / `generate` flows.
fn main() {
    println!("nonce-cracker Examples");
    println!("======================");
    println!();
    println!("This binary demonstrates usage patterns.");
    println!();
    println!("To run the actual tool, use:");
    println!("  cargo run -- example  # Run the built-in demonstration");
    println!("  cargo run -- run     # Run a search with signatures");
    println!();
    println!("See README.md for complete documentation.");
}
