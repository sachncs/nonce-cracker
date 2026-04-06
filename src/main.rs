//! # nonce-cracker - High-Speed Parallel ECDSA Private Key Recovery
//!
//! High-speed parallel ECDSA private key recovery for secp256k1 using an affine relation attack.
//!
//! ## Background
//!
//! In ECDSA, a signature `(r, s)` is computed as:
//!
//! ```text
//! r = (k·G).x mod n
//! s = k⁻¹(z + r·d) mod n
//! ```
//!
//! Where `k` is the nonce, `d` is the private key, `G` is the generator point,
//! and `n` is the curve order.
//!
//! When two signatures reuse a nonce with a linear relationship `k' = α·k + β`,
//! the private key can be recovered via:
//!
//! ```text
//! d = α·δ + β (mod n)
//! ```
//!
//! where `δ` is the unknown nonce offset that the tool searches for.
//!
//! ## Algorithm
//!
//! 1. Precompute α, β from the two signatures using BigInt (no overflow risk)
//! 2. Convert α, β to secp256k1 scalars for fast per-iteration arithmetic
//! 3. Search over δ values in parallel using Rayon
//! 4. For each δ, compute candidate `d = α·δ + β` and derive the public key
//! 5. Compare against the target public key (x-only precheck, then full match)
//! 6. Report the match with discovered δ and recovered private key d
//!
//! ## Usage
//!
//! ```bash
//! # Run demonstration (verifiable: recovers d = 0x3039)
//! nonce-cracker example
//!
//! # Recover with user-specified argument order
//! nonce-cracker recover --r1 <hex> --s1 <hex> --z1 <hex> \
//!   --r2 <hex> --s2 <hex> --z2 <hex> --pubkey <hex>
//!
//! # Recover with ECDSA argument order
//! nonce-cracker run --r1 <hex> --r2 <hex> --s1 <hex> --s2 <hex> \
//!   --z1 <hex> --z2 <hex> --pubkey <hex>
//! ```
//!
//! ## Exit Codes
//!
//! - `0`: Success (key found or search complete)
//! - `1`: Error (invalid input, I/O failure, etc.)
//!
//! ## Example
//!
//! ```rust,no_run
//! // See the 'run' command or 'example' command for complete usage.
//! // The tool accepts signature values (r1, r2, s1, s2, z1, z2) and
//! // a target public key, then searches for the private key.
//! ```

use clap::{Parser, Subcommand};
use hex::FromHex;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, PublicKey, Scalar,
};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Signed, Zero};
use rayon::prelude::*;
use std::{
    fs::File,
    io::Write,
    num::ParseIntError,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

/// The secp256k1 curve order (n).
///
/// This is the order of the secp256k1 elliptic curve group, used as the
/// modulus for all modular arithmetic in ECDSA operations.
///
/// ```text
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// ```
///
/// # Security Note
///
/// The cryptographic primitives use the `k256` crate, which has been
/// audited by Trail of Bits and is widely used in production.
/// The affine relation math itself is standard ECDSA mathematics.
const CURVE_ORDER_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Maximum allowed thread count to prevent resource exhaustion.
///
/// Setting threads beyond this value is likely counterproductive
/// as the search is memory-bound, not CPU-bound.
const MAX_THREADS: usize = 256;

/// Command-line argument parser.
///
/// Parses global flags and dispatches to subcommands.
/// Defaults to `example` command if no subcommand specified.
#[derive(Parser, Debug)]
#[command(
    name = "nonce-cracker",
    author,
    version,
    about = "High-speed parallel ECDSA key search for secp256k1",
    long_about = "nonce-cracker recovers private keys from two ECDSA signatures that share a nonce.
Uses affine relation attack for mathematical key recovery.
Run 'nonce-cracker example' for a demonstration, or 'nonce-cracker recover' with your signatures."
)]
struct Cli {
    /// The subcommand to execute.
    ///
    /// If omitted, defaults to `example` command.
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Available subcommands.
///
/// Each subcommand performs the same search operation but accepts
/// arguments in different orders for user convenience.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run search with signature values in fixed order: r1, r2, s1, s2, z1, z2.
    ///
    /// Use this when you have signature values in the traditional ECDSA order.
    ///
    /// # Example
    ///
    /// ```bash
    /// nonce-cracker run --r1 0x... --r2 0x... --s1 0x... --s2 0x... --z1 0x... --z2 0x... --pubkey 0x...
    /// ```
    #[command(name = "run")]
    Search {
        /// R value from first signature (hex string).
        ///
        /// The R coordinate of the point (k·G) from the first signature.
        #[arg(long)]
        r1: String,

        /// R value from second signature (hex string).
        ///
        /// The R coordinate of the point (k'·G) from the second signature.
        #[arg(long)]
        r2: String,

        /// S value from first signature (hex string).
        ///
        /// s = k⁻¹(z + r·d) mod n for the first signature.
        #[arg(long)]
        s1: String,

        /// S value from second signature (hex string).
        ///
        /// s' = k'⁻¹(z' + r'·d) mod n for the second signature.
        #[arg(long)]
        s2: String,

        /// Message hash for first signature (hex string, z1).
        ///
        /// The hash of the signed message, used in ECDSA calculation.
        #[arg(long)]
        z1: String,

        /// Message hash for second signature (hex string, z2).
        ///
        /// The hash of the second signed message.
        #[arg(long)]
        z2: String,

        /// Target public key (hex string).
        ///
        /// The public key to search for. Accepts uncompressed (04...), compressed (02/03...).
        #[arg(long)]
        pubkey: String,

        /// Search range start (decimal or hex with 0x prefix).
        ///
        /// Default: 0
        #[arg(long, default_value = "0")]
        start: String,

        /// Search range end (decimal or hex with 0x prefix).
        ///
        /// Default: 0x1000000000000000 (2^60)
        #[arg(long, default_value = "0x1000000000000000")]
        end: String,

        /// Search step size (decimal or hex with 0x prefix).
        ///
        /// Default: 1
        #[arg(long, default_value = "1")]
        step: String,

        /// Number of worker threads.
        ///
        /// Defaults to CPU core count if not specified.
        #[arg(long)]
        threads: Option<usize>,

        /// Suppress console output.
        ///
        /// When set, only writes to log file.
        #[arg(long, default_value = "false")]
        quiet: bool,

        /// Output log file path.
        ///
        /// Contains alpha, beta constants and search results.
        /// Default: search.log
        #[arg(long, default_value = "search.log")]
        outfile: String,
    },

    /// Recover private key with user-specified order: r1, s1, z1, r2, s2, z2.
    ///
    /// Use this when you want to specify signature values in the order
    /// r1, s1, z1 for the first signature and r2, s2, z2 for the second.
    ///
    /// # Example
    ///
    /// ```bash
    /// nonce-cracker recover --r1 0x... --s1 0x... --z1 0x... --r2 0x... --s2 0x... --z2 0x... --pubkey 0x...
    /// ```
    #[command(name = "recover")]
    Recover {
        /// R value from first signature (hex string).
        #[arg(long)]
        r1: String,

        /// S value from first signature (hex string).
        #[arg(long)]
        s1: String,

        /// Message hash for first signature (hex string, z1).
        #[arg(long)]
        z1: String,

        /// R value from second signature (hex string).
        #[arg(long)]
        r2: String,

        /// S value from second signature (hex string).
        #[arg(long)]
        s2: String,

        /// Message hash for second signature (hex string, z2).
        #[arg(long)]
        z2: String,

        /// Target public key (hex string).
        ///
        /// Accepts uncompressed (04...), compressed (02/03...).
        #[arg(long)]
        pubkey: String,

        /// Search range start.
        ///
        /// Default: 0
        #[arg(long, default_value = "0")]
        start: String,

        /// Search range end.
        ///
        /// Default: 0x1000000000000000 (2^60)
        #[arg(long, default_value = "0x1000000000000000")]
        end: String,

        /// Search step size.
        ///
        /// Default: 1
        #[arg(long, default_value = "1")]
        step: String,

        /// Number of worker threads.
        ///
        /// Defaults to CPU core count if not specified.
        #[arg(long)]
        threads: Option<usize>,

        /// Suppress console output.
        #[arg(long, default_value = "false")]
        quiet: bool,

        /// Output log file path.
        ///
        /// Default: search.log
        #[arg(long, default_value = "search.log")]
        outfile: String,
    },

    /// Run a demonstration with predefined test values.
    ///
    /// This command executes a search using generated test data
    /// where the private key d = 0x3039 is recovered.
    ///
    /// The demonstration:
    /// - Uses 4 threads
    /// - Searches range 0 to 2
    /// - Writes results to example.log
    #[command(name = "example")]
    Demo,
}

/// Application error types.
#[derive(Debug)]
enum Error {
    /// Hexadecimal string parsing failed.
    HexParse(String),

    /// Public key parsing failed.
    Pubkey(String),

    /// Numeric string parsing failed.
    NumberParse(String),

    /// Value is outside acceptable range.
    OutOfRange(String),

    /// File I/O operation failed.
    Io(String),

    /// Cryptographic calculation error.
    Calculation(String),
}

impl std::fmt::Display for Error {
    /// Formats the error for display to users.
    ///
    /// Provides human-readable error messages that explain what went wrong.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HexParse(s) => write!(f, "hex parse error: {s}"),
            Self::Pubkey(s) => write!(f, "public key parse error: {s}"),
            Self::NumberParse(s) => write!(f, "number parse error: {s}"),
            Self::OutOfRange(s) => write!(f, "out of range: {s}"),
            Self::Io(s) => write!(f, "io error: {s}"),
            Self::Calculation(s) => write!(f, "calculation error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self::HexParse(e.to_string())
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Self::NumberParse(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Result type alias.
type Result<T> = std::result::Result<T, Error>;

/// Main entry point.
fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Demo) {
        Commands::Demo => run_example(),

        Commands::Search {
            r1,
            r2,
            s1,
            s2,
            z1,
            z2,
            pubkey,
            start,
            end,
            step,
            threads,
            quiet,
            outfile,
        } => {
            let curve_order = parse_hex(CURVE_ORDER_HEX)?;
            let r1 = parse_hex(&r1)?;
            let r2 = parse_hex(&r2)?;
            let s1 = parse_hex(&s1)?;
            let s2 = parse_hex(&s2)?;
            let z1 = parse_hex(&z1)?;
            let z2 = parse_hex(&z2)?;
            let pk = parse_pubkey(&pubkey)?;
            let start = parse_number(&start)?;
            let end = parse_number(&end)?;
            let step = parse_number(&step)?;

            if step == 0 {
                return Err(Error::NumberParse("step must be > 0".into()));
            }

            search(
                r1,
                r2,
                s1,
                s2,
                z1,
                z2,
                pk,
                start,
                end,
                step,
                threads,
                quiet,
                &outfile,
                &curve_order,
            )
        }

        Commands::Recover {
            r1,
            r2,
            s1,
            s2,
            z1,
            z2,
            pubkey,
            start,
            end,
            step,
            threads,
            quiet,
            outfile,
        } => {
            let curve_order = parse_hex(CURVE_ORDER_HEX)?;
            let r1 = parse_hex(&r1)?;
            let r2 = parse_hex(&r2)?;
            let s1 = parse_hex(&s1)?;
            let s2 = parse_hex(&s2)?;
            let z1 = parse_hex(&z1)?;
            let z2 = parse_hex(&z2)?;
            let pk = parse_pubkey(&pubkey)?;
            let start = parse_number(&start)?;
            let end = parse_number(&end)?;
            let step = parse_number(&step)?;

            if step == 0 {
                return Err(Error::NumberParse("step must be > 0".into()));
            }

            search(
                r1,
                r2,
                s1,
                s2,
                z1,
                z2,
                pk,
                start,
                end,
                step,
                threads,
                quiet,
                &outfile,
                &curve_order,
            )
        }
    }
}

/// Runs the demonstration with predefined test values.
///
/// Generates two ECDSA signatures with affine nonce relation k' = k + 1,
/// such that the private key d = 0x3039 is recovered via d = α·δ + β.
fn run_example() -> Result<()> {
    let curve_order = parse_hex(CURVE_ORDER_HEX)?;

    // Generated test data: private key d = 0x3039
    // k' = k + 1, with delta = 1
    // alpha * 1 + beta = 0x3039
    let r1 = parse_hex("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba")?;
    let s1 = parse_hex("0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8")?;
    let z1 = parse_hex("0x0000000000000000000000000000000000000000000000000000000000000001")?;
    let r2 = parse_hex("0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12")?;
    let s2 = parse_hex("0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7")?;
    let z2 = parse_hex("0x0000000000000000000000000000000000000000000000000000000000000002")?;
    let pk = parse_pubkey("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")?;

    // Search range 0..=2: delta = 1 is within range, so d = 0x3039 will be found
    search(
        r1,
        r2,
        s1,
        s2,
        z1,
        z2,
        pk,
        0,
        2,
        1,
        Some(4),
        false,
        "example.log",
        &curve_order,
    )
}

/// Executes the parallel private key search.
///
/// Searches for δ such that the candidate private key d = α·δ + β
/// matches the target public key.
///
/// # Arguments
///
/// * `r1`, `r2` - R coordinates from the two signatures
/// * `s1`, `s2` - S values from the two signatures
/// * `z1`, `z2` - Message hashes from the two signatures
/// * `target_pk` - The public key to recover the private key for
/// * `start`, `end`, `step` - Search range parameters
/// * `threads` - Number of worker threads (None = auto-detect)
/// * `quiet` - Suppress console output
/// * `outfile` - Path for log output
/// * `curve_order` - The secp256k1 curve order
///
/// # Returns
///
/// `Ok(())` if search completed, or an error if inputs are invalid.
/// Results are written to the log file and optionally to stdout.
///
/// # Example
///
/// ```
/// let curve_order = parse_hex(CURVE_ORDER_HEX).unwrap();
/// let r1 = parse_hex("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba").unwrap();
/// // ... (see run_example for full setup)
/// search(r1, r2, s1, s2, z1, z2, pk, 0, 10, 1, Some(4), false, "search.log", &curve_order)?;
/// ```
#[allow(clippy::too_many_arguments)]
fn search(
    r1: BigInt,
    r2: BigInt,
    s1: BigInt,
    s2: BigInt,
    z1: BigInt,
    z2: BigInt,
    target_pk: PublicKey,
    start: u64,
    end: u64,
    step: u64,
    threads: Option<usize>,
    quiet: bool,
    outfile: &str,
    curve_order: &BigInt,
) -> Result<()> {
    // Validate range
    if end < start {
        return Err(Error::OutOfRange("end must be >= start".into()));
    }

    // Validate and bound thread count
    let thread_count = match threads {
        Some(t) if t > MAX_THREADS => {
            log::warn!("Thread count {t} exceeds maximum {MAX_THREADS}, capping to {MAX_THREADS}");
            MAX_THREADS
        }
        Some(t) => t,
        None => thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
            .min(MAX_THREADS),
    };

    // Precompute affine relation constants
    let (alpha, beta) = precompute(&r1, &r2, &s1, &s2, &z1, &z2, curve_order)?;

    // Generate unique log path to avoid collisions
    let log_path = unique_log_path(outfile);

    // Write constants to log
    let mut log_file = File::create(&log_path)?;
    writeln!(log_file, "alpha: 0x{}", hex_string(&alpha))?;
    writeln!(log_file, "beta:  0x{}", hex_string(&beta))?;

    // Convert to scalars for fast computation
    let (alpha_s, beta_s) = (
        bigint_to_scalar(&alpha)
            .ok_or_else(|| Error::OutOfRange("alpha outside scalar range".into()))?,
        bigint_to_scalar(&beta)
            .ok_or_else(|| Error::OutOfRange("beta outside scalar range".into()))?,
    );

    // Precompute step for fast iteration
    let step_scalar = alpha_s * Scalar::from(step);
    let step_point = ProjectivePoint::GENERATOR * step_scalar;

    // Extract target pubkey bytes for comparison
    let target_bytes = target_pk.to_encoded_point(true).as_bytes().to_vec();
    let target_x = &target_bytes[1..33];

    // Setup parallel search
    let total: u128 = ((end as u128 - start as u128) / step as u128) + 1;
    let chunk: u128 = total.div_ceil(thread_count as u128);

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(parking_lot::Mutex::new(None::<(Scalar, u64)>));

    log::info!(
        "search start=0x{:x} end=0x{:x} step={} threads={}",
        start,
        end,
        step,
        thread_count
    );

    // Execute parallel search
    (0..thread_count).into_par_iter().for_each(|thread_id| {
        let chunk_start = thread_id as u128 * chunk;
        if chunk_start >= total || found.load(Ordering::Relaxed) {
            return;
        }
        let count = chunk.min(total - chunk_start);

        // Initialize this chunk's starting point
        let mut delta = start as u128 + chunk_start * step as u128;
        let mut cur_scalar = compute_private_key(delta as u64, alpha_s, beta_s);
        let mut point = ProjectivePoint::GENERATOR * cur_scalar;

        // Search this chunk
        for _ in 0..count {
            if found.load(Ordering::Relaxed) {
                break;
            }
            if is_match(&point, target_x, &target_bytes) {
                if !found.swap(true, Ordering::SeqCst) {
                    *result.lock() = Some((cur_scalar, delta as u64));
                }
                break;
            }
            // Advance to next point
            point += step_point;
            cur_scalar += step_scalar;
            delta = delta.wrapping_add(step as u128);
        }
    });

    // Report results
    let found_result = *result.lock();

    if let Some((d, delta)) = found_result {
        let hex = scalar_hex(&d);
        writeln!(log_file, "FOUND delta=0x{:x} d=0x{hex}", delta)?;
        if !quiet {
            println!(
                "FOUND delta=0x{:x} d=0x{hex} (written to {log_path})",
                delta
            );
        }
        log::info!("FOUND delta=0x{:x} d=0x{hex}", delta);
    } else {
        writeln!(log_file, "No key found in searched range.")?;
        if !quiet {
            println!("No key found in searched range. Results in {log_path}");
        }
        log::warn!("No key found in searched range.");
    }

    Ok(())
}

/// Computes d = α·δ + β (mod n).
///
/// Core formula for the affine relation attack.
#[inline(always)]
fn compute_private_key(delta: u64, alpha: Scalar, beta: Scalar) -> Scalar {
    alpha * Scalar::from(delta) + beta
}

/// Checks if a point matches the target public key.
///
/// Uses x-only precheck first (comparing only x-coordinate),
/// then full compressed key comparison.
#[inline(always)]
fn is_match(point: &ProjectivePoint, target_x: &[u8], target_full: &[u8]) -> bool {
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    bytes[1..33] == *target_x && *bytes == *target_full
}

/// Computes the modular inverse using the extended Euclidean algorithm.
///
/// Finds a⁻¹ mod n such that a · a⁻¹ ≡ 1 (mod n).
///
/// # Arguments
///
/// * `a` - The value to invert
/// * `n` - The modulus (must be positive)
///
/// # Returns
///
/// The value a⁻¹ mod n, or `None` if no inverse exists (i.e., gcd(a, n) ≠ 1).
///
/// # Example
///
/// ```
/// let n = parse_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap();
/// let a = BigInt::from(7u64);
/// let inv = mod_inverse(&a, &n).unwrap();
/// let prod = (a * inv) % &n;
/// assert_eq!(prod, BigInt::one());
/// ```
fn mod_inverse(a: &BigInt, n: &BigInt) -> Result<BigInt> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = normalize(a, n);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let temp_t = &t - &quotient * &new_t;
        t = new_t;
        new_t = temp_t;
        let temp_r = &r - &quotient * &new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r > BigInt::one() {
        return Err(Error::Calculation("No modular inverse exists".into()));
    }
    if t.is_negative() {
        t += n;
    }
    Ok(t)
}

/// Precomputes α and β constants for the affine relation attack.
///
/// Given two ECDSA signatures (r1, s1) and (r2, s2) that share a nonce
/// with linear relation k' = α·k + β, this function computes α and β.
///
/// # Arguments
///
/// * `r1` - R coordinate of the first signature
/// * `r2` - R coordinate of the second signature
/// * `s1` - S value of the first signature
/// * `s2` - S value of the second signature
/// * `z1` - Message hash of the first signature
/// * `z2` - Message hash of the second signature
/// * `n` - The secp256k1 curve order
///
/// # Returns
///
/// A tuple `(α, β)` for use in the affine relation formula d = α·δ + β.
///
/// # Example
///
/// ```
/// let n = parse_hex(CURVE_ORDER_HEX).unwrap();
/// let r1 = BigInt::from(1u8);
/// let r2 = BigInt::from(2u8);
/// let s1 = BigInt::from(3u8);
/// let s2 = BigInt::from(4u8);
/// let z1 = BigInt::from(5u8);
/// let z2 = BigInt::from(6u8);
///
/// let (alpha, beta) = precompute(&r1, &r2, &s1, &s2, &z1, &z2, &n).unwrap();
/// ```
fn precompute(
    r1: &BigInt,
    r2: &BigInt,
    s1: &BigInt,
    s2: &BigInt,
    z1: &BigInt,
    z2: &BigInt,
    n: &BigInt,
) -> Result<(BigInt, BigInt)> {
    let u = mod_inverse(s1, n)?;
    let a = normalize(&(s2 * r1 * &u - r2), n);
    let b = normalize(&(z2 - s2 * z1 * &u), n);
    let c = normalize(s2, n);
    let a_inv = mod_inverse(&a, n)?;
    let alpha = normalize(&(-&c * &a_inv), n);
    let beta = normalize(&(b * &a_inv), n);
    Ok((alpha, beta))
}

/// Normalizes x to a positive modular representative in [0, n).
///
/// # Arguments
///
/// * `x` - The value to normalize
/// * `n` - The modulus
///
/// # Returns
///
/// The value in range [0, n).
fn normalize(x: &BigInt, n: &BigInt) -> BigInt {
    let r = x % n;
    if r.is_negative() {
        r + n
    } else {
        r
    }
}

/// Parses a hex string into a BigInt.
///
/// Accepts hex strings with or without `0x` prefix.
/// Odd-length strings are padded with a leading zero.
///
/// # Arguments
///
/// * `s` - The hex string to parse
///
/// # Returns
///
/// The parsed BigInt value.
///
/// # Example
///
/// ```
/// let val = parse_hex("0xFF").unwrap();
/// assert_eq!(val, BigInt::from(255));
///
/// let val2 = parse_hex("FF").unwrap();
/// assert_eq!(val2, BigInt::from(255));
///
/// // Odd-length padding works automatically
/// let val3 = parse_hex("0xFFF").unwrap();
/// let val4 = parse_hex("0x0FFF").unwrap();
/// assert_eq!(val3, val4);
/// ```
fn parse_hex(s: &str) -> Result<BigInt> {
    let raw = s.trim_start_matches("0x");
    let padded;
    let s = if raw.len() % 2 == 1 {
        padded = format!("0{raw}");
        padded.as_str()
    } else {
        raw
    };
    let bytes = Vec::from_hex(s)?;
    Ok(BigInt::from_bytes_be(Sign::Plus, &bytes))
}

/// Parses a public key from a hex string.
///
/// # Arguments
///
/// * `hex_pk` - The hex-encoded public key
///
/// # Supported Formats
///
/// * Uncompressed: `04` + x (32 bytes) + y (32 bytes) = 130 hex chars
/// * Compressed (even y): `02` + x (32 bytes) = 66 hex chars
/// * Compressed (odd y): `03` + x (32 bytes) = 66 hex chars
///
/// # Returns
///
/// The parsed `PublicKey`, or an error if the format is invalid.
///
/// # Example
///
/// ```
/// // Compressed public key
/// let pk = parse_pubkey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
///
/// // Uncompressed public key
/// let pk2 = parse_pubkey("04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
/// ```
fn parse_pubkey(hex_pk: &str) -> Result<PublicKey> {
    let bytes = Vec::from_hex(hex_pk.trim_start_matches("0x"))?;
    match bytes.first() {
        Some(0x02) | Some(0x03) => {
            // Compressed format - directly parse
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error::Pubkey(e.to_string()))
        }
        Some(0x04) => {
            // Uncompressed format - convert to compressed
            let x = &bytes[1..33];
            let y = &bytes[33..65];
            let parity = y[31] & 1;
            let mut comp = vec![if parity == 0 { 0x02 } else { 0x03 }];
            comp.extend_from_slice(x);
            PublicKey::from_sec1_bytes(&comp).map_err(|e| Error::Pubkey(e.to_string()))
        }
        _ => Err(Error::Pubkey(
            "Unsupported public key format. Use 02, 03, or 04 prefix".into(),
        )),
    }
}

/// Parses a number string as u64.
///
/// Accepts decimal notation (e.g., `1000000`) or hex with `0x`/`0X` prefix
/// (e.g., `0xFF`).
///
/// # Arguments
///
/// * `s` - The number string to parse
///
/// # Returns
///
/// The parsed u64 value.
///
/// # Example
///
/// ```
/// assert_eq!(parse_number("0").unwrap(), 0);
/// assert_eq!(parse_number("100").unwrap(), 100);
/// assert_eq!(parse_number("0xFF").unwrap(), 255);
/// assert_eq!(parse_number("0Xff").unwrap(), 255);
/// ```
fn parse_number(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| Error::NumberParse(e.to_string()))
    } else {
        s.parse::<u64>()
            .map_err(|e| Error::NumberParse(e.to_string()))
    }
}

/// Converts a BigInt to a Scalar if within curve order.
fn bigint_to_scalar(d: &BigInt) -> Option<Scalar> {
    if d.is_negative() {
        return None;
    }
    let (_, mut bytes) = d.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    while bytes.len() < 32 {
        bytes.insert(0, 0u8);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_repr(arr.into()).into()
}

/// Generates a unique log file path with timestamp.
fn unique_log_path(default_path: &str) -> String {
    if default_path == "search.log" {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("search_{timestamp}.log")
    } else {
        default_path.to_string()
    }
}

/// Converts a BigInt to hex string without 0x prefix.
fn hex_string(x: &BigInt) -> String {
    let (_, bytes) = x.to_bytes_be();
    if bytes.is_empty() {
        "0".into()
    } else {
        hex::encode(bytes)
    }
}

/// Converts a Scalar to hex string without 0x prefix.
fn scalar_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

// Unit tests for cryptographic functions
#[cfg(test)]
mod tests {
    use super::*;

    /// Tests modular inverse computation.
    ///
    /// Verifies that a * a⁻¹ ≡ 1 (mod n) for a = 7.
    #[test]
    fn test_mod_inverse() {
        let n = parse_hex(CURVE_ORDER_HEX).unwrap();
        let a = BigInt::from(7u64);
        let inv = mod_inverse(&a, &n).unwrap();
        let prod = (a * inv) % &n;
        assert_eq!(prod, BigInt::one());
    }

    /// Tests that d = α·0 + β = β when delta = 0.
    #[test]
    fn test_precompute_and_private_key() {
        let n = parse_hex(CURVE_ORDER_HEX).unwrap();
        let r1 = BigInt::from(1u8);
        let r2 = BigInt::from(2u8);
        let s1 = BigInt::from(3u8);
        let s2 = BigInt::from(4u8);
        let z1 = BigInt::from(5u8);
        let z2 = BigInt::from(6u8);

        let (alpha, beta) = precompute(&r1, &r2, &s1, &s2, &z1, &z2, &n).unwrap();
        let d0 = compute_private_key(
            0,
            bigint_to_scalar(&alpha).unwrap(),
            bigint_to_scalar(&beta).unwrap(),
        );
        assert_eq!(
            scalar_hex(&d0),
            scalar_hex(&bigint_to_scalar(&beta).unwrap())
        );
    }

    /// Tests public key parsing and round-trip conversion.
    #[test]
    fn test_pubkey_conversion() {
        let pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk = parse_pubkey(pk_hex).unwrap();
        let encoded = pk.to_encoded_point(true);
        assert_eq!(hex::encode(encoded.as_bytes()), pk_hex);
    }

    /// Tests hex string parsing with various formats.
    #[test]
    fn test_hex_parsing() {
        // With 0x prefix
        let val = parse_hex("0xFF").unwrap();
        assert_eq!(val, BigInt::from(255));

        // Without prefix
        let val2 = parse_hex("FF").unwrap();
        assert_eq!(val2, BigInt::from(255));

        // Odd-length padding
        let val3 = parse_hex("0xFFF").unwrap();
        let val4 = parse_hex("0x0FFF").unwrap();
        assert_eq!(val3, val4);
    }

    /// Tests range number parsing with decimal and hex.
    #[test]
    fn test_range_number_parsing() {
        assert_eq!(parse_number("0").unwrap(), 0);
        assert_eq!(parse_number("100").unwrap(), 100);
        assert_eq!(parse_number("0xFF").unwrap(), 255);
        assert_eq!(parse_number("0Xff").unwrap(), 255);
    }
}
