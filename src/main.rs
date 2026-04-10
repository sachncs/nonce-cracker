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
//! The search is a bounded exhaustive scan over a signed interval:
//!
//! 1. Parse and validate the signature pair, public key, and search bounds.
//! 2. Derive affine constants `alpha` and `beta` from the two signatures.
//! 3. Convert those constants to secp256k1 scalars when they fit in-field.
//! 4. Partition the inclusive `delta` window across a dedicated Rayon pool.
//! 5. Evaluate `d = alpha * delta + beta mod n` for each candidate.
//! 6. Reconstruct the compressed public key from `d` and compare it to the
//!    target using an x-coordinate precheck followed by exact SEC1 equality.
//! 7. Record the first match in the report file and emit a structured summary.
//!
//! ## Invariants
//!
//! - The search interval is inclusive and `step > 0`.
//! - The report path is resolved into the configured log directory unless an
//!   absolute path is passed explicitly.
//! - A found result stops the search; later candidates are ignored.
//! - All arithmetic is performed modulo the secp256k1 curve order.
//!
//! ## Complexity
//!
//! Let `N = floor((end - start) / step) + 1`.
//!
//! - Time: `O(N)` candidate evaluations in the worst case.
//! - Space: `O(1)` worker-local state, plus the report file and small
//!   coordination state (`AtomicBool` + mutex-protected result slot).
//!
//! The implementation is parallelized across workers, so wall-clock latency
//! depends on the candidate density and the available CPU cores.
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
    io::{BufWriter, Write},
    num::ParseIntError,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

mod logging;

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

/// Monotonic counter used to guarantee unique default log-file names.
static LOG_FILE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Command-line argument parser.
///
/// Parses global flags and dispatches to subcommands. If no subcommand is
/// provided, the bundled example is executed.
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

/// Parsed CLI inputs shared by `run` and `recover`.
///
/// This internal transfer object normalizes the two command variants before
/// the shared validation and search pipeline runs.
struct SearchArgs {
    r1: String,
    r2: String,
    s1: String,
    s2: String,
    z1: String,
    z2: String,
    pubkey: String,
    start: String,
    end: String,
    step: String,
    threads: Option<usize>,
    quiet: bool,
    outfile: String,
}

/// Available subcommands.
///
/// `run` and `recover` execute the same search pipeline with different
/// argument orderings for convenience at the call site. `example` is a
/// deterministic self-test that exercises the full stack with fixed data.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run the search with signature values in ECDSA order:
    /// `r1, r2, s1, s2, z1, z2`.
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
        #[arg(long, default_value = "0", allow_hyphen_values = true)]
        start: String,

        /// Search range end (decimal or hex with 0x prefix).
        ///
        /// Default: 0x1000000000000000 (2^60)
        #[arg(long, default_value = "0x1000000000000000", allow_hyphen_values = true)]
        end: String,

        /// Search step size (decimal or hex with 0x prefix).
        ///
        /// Default: 1
        #[arg(long, default_value = "1", allow_hyphen_values = true)]
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

    /// Run the search with grouped signature values:
    /// `r1, s1, z1, r2, s2, z2`.
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
        #[arg(long, default_value = "0", allow_hyphen_values = true)]
        start: String,

        /// Search range end.
        ///
        /// Default: 0x1000000000000000 (2^60)
        #[arg(long, default_value = "0x1000000000000000", allow_hyphen_values = true)]
        end: String,

        /// Search step size.
        ///
        /// Default: 1
        #[arg(long, default_value = "1", allow_hyphen_values = true)]
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

    /// Run the bundled demonstration search and recover the fixed private key `0x3039`.
    ///
    /// The example exists as a correctness smoke test and documentation
    /// anchor: it searches a 3-value range with fixed ECDSA inputs and
    /// produces a predictable report.
    ///
    /// # Example
    ///
    /// ```bash
    /// nonce-cracker example
    /// ```
    #[command(name = "example")]
    Example,
}

/// Application error types.
///
/// The error surface is intentionally small and preserves the stage at which
/// the failure occurred: parsing, range validation, cryptography, I/O, logging,
/// or Rayon pool construction.
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

    /// Rayon thread pool construction failed.
    ThreadPool(String),

    /// Logging initialization or path resolution failed.
    Logging(String),
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
            Self::ThreadPool(s) => write!(f, "thread pool error: {s}"),
            Self::Logging(s) => write!(f, "logging error: {s}"),
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

impl From<logging::LoggingError> for Error {
    fn from(err: logging::LoggingError) -> Self {
        Self::Logging(err.to_string())
    }
}

/// Result type alias.
type Result<T> = std::result::Result<T, Error>;

/// Main entry point.
///
/// The binary initializes logging before dispatching into the CLI branch so
/// that all modules share the same backend and log directory policy.
fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init_from_env()?;

    match cli.command.unwrap_or(Commands::Example) {
        Commands::Example => run_example_command(),

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
        } => run_search_command(SearchArgs {
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
        }),

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
        } => run_search_command(SearchArgs {
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
        }),
    }
}

/// Parses CLI arguments, validates them once, and executes the search.
///
/// The function owns the shared parsing path for `run` and `recover` so the
/// two command variants cannot drift semantically.
fn run_search_command(args: SearchArgs) -> Result<()> {
    let curve_order = parse_bigint_hex(CURVE_ORDER_HEX)?;
    let r1 = parse_bigint_hex(&args.r1)?;
    let r2 = parse_bigint_hex(&args.r2)?;
    let s1 = parse_bigint_hex(&args.s1)?;
    let s2 = parse_bigint_hex(&args.s2)?;
    let z1 = parse_bigint_hex(&args.z1)?;
    let z2 = parse_bigint_hex(&args.z2)?;
    let pk = parse_public_key(&args.pubkey)?;
    let start = parse_bounded_integer(&args.start)?;
    let end = parse_bounded_integer(&args.end)?;
    let step = parse_bounded_integer(&args.step)?;

    if step == 0 {
        return Err(Error::OutOfRange("step must be > 0".into()));
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
        args.threads,
        args.quiet,
        &args.outfile,
        &curve_order,
    )
}

/// Runs the bundled demonstration search with predefined test values.
///
/// The example uses two signatures with nonce relation `k' = k + 1` and a
/// known private key so the result is reproducible. This is a correctness
/// smoke test, not a benchmark or a security test.
fn run_example_command() -> Result<()> {
    let curve_order = parse_bigint_hex(CURVE_ORDER_HEX)?;

    // Generated test data: private key d = 0x3039
    // k' = k + 1, with delta = 1
    // alpha * 1 + beta = 0x3039
    let r1 =
        parse_bigint_hex("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba")?;
    let s1 =
        parse_bigint_hex("0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8")?;
    let z1 =
        parse_bigint_hex("0x0000000000000000000000000000000000000000000000000000000000000001")?;
    let r2 =
        parse_bigint_hex("0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12")?;
    let s2 =
        parse_bigint_hex("0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7")?;
    let z2 =
        parse_bigint_hex("0x0000000000000000000000000000000000000000000000000000000000000002")?;
    let pk =
        parse_public_key("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")?;

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
        None,
        false,
        "example.log",
        &curve_order,
    )
}

/// Executes the parallel private key search.
///
/// Searches a bounded signed-delta interval for the candidate private key
/// `d = alpha * delta + beta` that matches the target public key. The
/// implementation is intentionally exhaustive within the requested window so
/// correctness is deterministic given the same inputs and bounds.
///
/// # Arguments
///
/// * `r1`, `r2` - R coordinates from the two signatures
/// * `s1`, `s2` - S values from the two signatures
/// * `z1`, `z2` - Message hashes from the two signatures
/// * `target_public_key` - Target public key used to validate candidates
/// * `start`, `end`, `step` - Inclusive signed search bounds and positive step
/// * `threads` - Number of worker threads (None = auto-detect)
/// * `quiet` - Suppress console output
/// * `outfile` - Path for log output
/// * `curve_order` - secp256k1 curve order used for modular arithmetic
///
/// # Returns
///
/// `Ok(())` if the search completes; otherwise returns a structured error.
/// Results are written to the report file and optionally mirrored to stdout.
///
/// # Preconditions
///
/// - `step > 0`
/// - `end >= start`
/// - `outfile` is non-empty after trimming
/// - `alpha` and `beta` fit into secp256k1 scalars
///
/// # Postconditions
///
/// - The report file exists on return.
/// - A match is reported at most once.
/// - No candidate outside the requested interval is evaluated.
///
/// # Complexity
///
/// Time is linear in the number of search candidates; space is constant
/// except for the output file and bounded coordination state.
///
/// # Example
///
/// ```
/// let curve_order = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();
/// let r1 = parse_bigint_hex("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba").unwrap();
/// // ... (see run_example_command for full setup)
/// search(r1, r2, s1, s2, z1, z2, pk, 0, 10, 1, None, false, "search.log", &curve_order)?;
/// ```
#[allow(clippy::too_many_arguments)]
fn search(
    r1: BigInt,
    r2: BigInt,
    s1: BigInt,
    s2: BigInt,
    z1: BigInt,
    z2: BigInt,
    target_public_key: PublicKey,
    start: i64,
    end: i64,
    step: i64,
    threads: Option<usize>,
    quiet: bool,
    outfile: &str,
    curve_order: &BigInt,
) -> Result<()> {
    // Validate range
    if end < start {
        return Err(Error::OutOfRange("end must be >= start".into()));
    }
    if matches!(threads, Some(0)) {
        return Err(Error::OutOfRange("threads must be > 0".into()));
    }
    if outfile.trim().is_empty() {
        return Err(Error::OutOfRange("outfile must not be empty".into()));
    }
    if step <= 0 {
        return Err(Error::OutOfRange("step must be > 0".into()));
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
    let (alpha, beta) = derive_affine_constants(&r1, &r2, &s1, &s2, &z1, &z2, curve_order)?;

    // Generate unique log path to avoid collisions
    let output_log_path = resolve_report_path(outfile)?;
    if let Some(parent) = output_log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write constants to log
    let mut log_file = BufWriter::new(File::create(&output_log_path)?);
    writeln!(log_file, "alpha: 0x{}", bigint_to_lower_hex(&alpha))?;
    writeln!(log_file, "beta:  0x{}", bigint_to_lower_hex(&beta))?;

    // Convert to scalars for fast computation
    let (alpha_scalar, beta_scalar) = (
        bigint_to_scalar_opt(&alpha)
            .ok_or_else(|| Error::OutOfRange("alpha outside scalar range".into()))?,
        bigint_to_scalar_opt(&beta)
            .ok_or_else(|| Error::OutOfRange("beta outside scalar range".into()))?,
    );

    // Precompute step for fast iteration
    let step_scalar = alpha_scalar * Scalar::from(step.unsigned_abs());
    let step_point = ProjectivePoint::GENERATOR * step_scalar;

    // Extract target pubkey bytes for comparison
    let target_encoded = target_public_key.to_encoded_point(true);
    let target_encoded_bytes = target_encoded.as_bytes();
    let target_x_bytes = &target_encoded_bytes[1..33];

    // Setup parallel search
    let span = (end as i128)
        .checked_sub(start as i128)
        .ok_or_else(|| Error::OutOfRange("search range overflow".into()))?;
    if span < 0 {
        return Err(Error::OutOfRange("end must be >= start".into()));
    }
    let step_i128 = step as i128;
    let total: u128 = (span / step_i128 + 1)
        .try_into()
        .map_err(|_| Error::OutOfRange("search range is too large".into()))?;
    let chunk: u128 = total.div_ceil(thread_count as u128);

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(parking_lot::Mutex::new(None::<i64>));

    log::info!(
        "search start=0x{:x} end=0x{:x} step={} threads={}",
        start,
        end,
        step,
        thread_count
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .map_err(|e| Error::ThreadPool(e.to_string()))?;

    // Execute parallel search on a dedicated pool so --threads is honored.
    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|thread_id| {
            let chunk_start = thread_id as u128 * chunk;
            if chunk_start >= total || found.load(Ordering::Acquire) {
                return;
            }
            let count = chunk.min(total - chunk_start);

            // Initialize this chunk's starting point.
            let mut candidate_delta = start as i128 + chunk_start as i128 * step_i128;
            let delta_i64 = match i64::try_from(candidate_delta) {
                Ok(delta_i64) => delta_i64,
                Err(_) => return,
            };
            let mut point = ProjectivePoint::GENERATOR
                * derive_private_key(delta_i64, alpha_scalar, beta_scalar);

            // Search this chunk.
            for _ in 0..count {
                if found.load(Ordering::Acquire) {
                    break;
                }
                if matches_target_public_key(&point, target_x_bytes, target_encoded_bytes) {
                    if !found.swap(true, Ordering::AcqRel) {
                        if let Ok(delta_i64) = i64::try_from(candidate_delta) {
                            *result.lock() = Some(delta_i64);
                        }
                    }
                    break;
                }
                // Advance to the next candidate without reallocating.
                point += step_point;
                candidate_delta += step_i128;
            }
        });
    });

    // Report results
    let found_result = *result.lock();

    if let Some(delta) = found_result {
        let d = derive_private_key(delta, alpha_scalar, beta_scalar);
        let hex = scalar_to_lower_hex(&d);
        writeln!(log_file, "FOUND delta={delta} d=0x{hex}")?;
        logging::emit_summary(
            log::Level::Info,
            format!(
                "event=search_result status=found delta={delta} d=0x{hex} report={}",
                output_log_path.display()
            ),
            !quiet,
        );
    } else {
        writeln!(log_file, "No key found in searched range.")?;
        logging::emit_summary(
            log::Level::Warn,
            format!(
                "event=search_result status=missing report={}",
                output_log_path.display()
            ),
            !quiet,
        );
    }

    Ok(())
}

/// Computes the bounded signed-delta candidate `d = alpha * delta + beta`.
///
/// Negative deltas are represented by subtracting the corresponding scalar,
/// which keeps the arithmetic correct modulo the curve order.
#[inline(always)]
fn derive_private_key(delta: i64, alpha: Scalar, beta: Scalar) -> Scalar {
    let delta_scalar = Scalar::from(delta.unsigned_abs());
    if delta.is_negative() {
        beta - alpha * delta_scalar
    } else {
        alpha * delta_scalar + beta
    }
}

/// Checks whether a candidate point matches the target public key.
///
/// The x-coordinate is compared first to reject most candidates quickly,
/// then the full compressed SEC1 encoding is checked for exact equality.
#[inline(always)]
fn matches_target_public_key(
    point: &ProjectivePoint,
    target_x_bytes: &[u8],
    target_full: &[u8],
) -> bool {
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    bytes[1..33] == *target_x_bytes && *bytes == *target_full
}

/// Computes the modular inverse using the extended Euclidean algorithm.
///
/// Finds a⁻¹ mod n such that a · a⁻¹ ≡ 1 (mod n).
///
/// # Complexity
///
/// `O(log n)` arithmetic steps.
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
/// let n = parse_bigint_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap();
/// let a = BigInt::from(7u64);
/// let inv = modular_inverse(&a, &n).unwrap();
/// let prod = (a * inv) % &n;
/// assert_eq!(prod, BigInt::one());
/// ```
fn modular_inverse(a: &BigInt, n: &BigInt) -> Result<BigInt> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = n.clone();
    let mut new_r = normalize_modulo(a, n);

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
/// The implementation first derives the linear equation
/// `a * d = b - c * delta (mod n)` and then solves it for
/// `d = alpha * delta + beta (mod n)` when `a` is invertible.
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
/// # Complexity
///
/// Constant-time modular algebra relative to the input size; the dominant
/// cost is a pair of modular inversions on arbitrary-precision integers.
///
/// # Example
///
/// ```
/// let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();
/// let r1 = BigInt::from(1u8);
/// let r2 = BigInt::from(2u8);
/// let s1 = BigInt::from(3u8);
/// let s2 = BigInt::from(4u8);
/// let z1 = BigInt::from(5u8);
/// let z2 = BigInt::from(6u8);
///
/// let (alpha, beta) = derive_affine_constants(&r1, &r2, &s1, &s2, &z1, &z2, &n).unwrap();
/// ```
fn derive_affine_constants(
    r1: &BigInt,
    r2: &BigInt,
    s1: &BigInt,
    s2: &BigInt,
    z1: &BigInt,
    z2: &BigInt,
    n: &BigInt,
) -> Result<(BigInt, BigInt)> {
    let u = modular_inverse(s1, n)?;
    let a = normalize_modulo(&(s2 * r1 * &u - r2), n);
    let b = normalize_modulo(&(z2 - s2 * z1 * &u), n);
    let c = normalize_modulo(s2, n);
    let a_inv = modular_inverse(&a, n)?;
    let alpha = normalize_modulo(&(-&c * &a_inv), n);
    let beta = normalize_modulo(&(b * &a_inv), n);
    Ok((alpha, beta))
}

/// Normalizes x to a positive modular representative in [0, n).
///
/// Converts any integer x to its canonical representative in the range [0, n)
/// by computing x mod n and adjusting if negative.
///
/// # Arguments
///
/// * `x` - The value to normalize_modulo
/// * `n` - The modulus (must be positive)
///
/// # Returns
///
/// The value in range [0, n).
///
/// # Example
///
/// ```
/// let n = BigInt::from(10);
/// assert_eq!(normalize_modulo(&BigInt::from(-3), &n), BigInt::from(7));
/// assert_eq!(normalize_modulo(&BigInt::from(5), &n), BigInt::from(5));
/// ```
fn normalize_modulo(x: &BigInt, n: &BigInt) -> BigInt {
    let r = x % n;
    if r.is_negative() {
        r + n
    } else {
        r
    }
}

/// Parses a hexadecimal string into a non-negative `BigInt`.
///
/// Accepts hex strings with or without a `0x`/`0X` prefix and ignores
/// surrounding whitespace. Odd-length strings are padded with a leading zero.
///
/// # Errors
///
/// Returns an error for empty input or invalid hex digits.
///
/// # Arguments
///
/// * `s` - The hex string to parse
///
/// # Returns
///
/// The parsed `BigInt` value.
///
/// Returns an error for empty input or invalid hex digits.
///
/// # Example
///
/// ```
/// let val = parse_bigint_hex("0xFF").unwrap();
/// assert_eq!(val, BigInt::from(255));
///
/// let val2 = parse_bigint_hex("FF").unwrap();
/// assert_eq!(val2, BigInt::from(255));
///
/// // Odd-length padding works automatically
/// let val3 = parse_bigint_hex("0xFFF").unwrap();
/// let val4 = parse_bigint_hex("0x0FFF").unwrap();
/// assert_eq!(val3, val4);
/// ```
fn parse_bigint_hex(s: &str) -> Result<BigInt> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Err(Error::HexParse("empty hex string".into()));
    }
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
/// The function accepts SEC1 compressed and uncompressed encodings and
/// validates the full point encoding with `k256`.
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
/// The parsed `PublicKey`, or an error if the SEC1 encoding is invalid.
///
/// Compressed keys must be 33 bytes and uncompressed keys must be 65 bytes.
///
/// # Example
///
/// ```
/// // Compressed public key
/// let pk = parse_public_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
///
/// // Uncompressed public key
/// let pk2 = parse_public_key("04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
/// ```
fn parse_public_key(hex_pk: &str) -> Result<PublicKey> {
    let bytes = Vec::from_hex(
        hex_pk
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
    )?;
    match bytes.first() {
        Some(0x02) | Some(0x03) => {
            // Compressed format requires exactly 33 bytes
            if bytes.len() != 33 {
                return Err(Error::Pubkey(
                    "invalid length for compressed public key".into(),
                ));
            }
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error::Pubkey(e.to_string()))
        }
        Some(0x04) => {
            // Uncompressed format requires exactly 65 bytes
            if bytes.len() != 65 {
                return Err(Error::Pubkey(
                    "invalid length for uncompressed public key".into(),
                ));
            }
            // Validate the full SEC1 encoding instead of reconstructing a compressed point.
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error::Pubkey(e.to_string()))
        }
        _ => Err(Error::Pubkey(
            "Unsupported public key format. Use 02, 03, or 04 prefix".into(),
        )),
    }
}

/// Parses a decimal or hexadecimal string into a bounded signed integer.
///
/// Accepts decimal notation (e.g., `1000000`) or hex with `0x`/`0X` prefix
/// (e.g., `0xFF`). A leading `-` is supported so the CLI can express signed
/// search bounds.
///
/// # Complexity
///
/// Linear in the length of the input string.
///
/// # Arguments
///
/// * `s` - The number string to parse
///
/// # Returns
///
/// The parsed `i64` value.
///
/// Returns an error if the value overflows `i64` or contains invalid digits.
///
/// # Example
///
/// ```
/// assert_eq!(parse_bounded_integer("0").unwrap(), 0);
/// assert_eq!(parse_bounded_integer("100").unwrap(), 100);
/// assert_eq!(parse_bounded_integer("0xFF").unwrap(), 255);
/// assert_eq!(parse_bounded_integer("-0xFF").unwrap(), -255);
/// ```
fn parse_bounded_integer(s: &str) -> Result<i64> {
    let s = s.trim();
    let (negative, body) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };

    let magnitude = if body.starts_with("0x") || body.starts_with("0X") {
        u128::from_str_radix(&body[2..], 16).map_err(|e| Error::NumberParse(e.to_string()))?
    } else {
        body.parse::<u128>()
            .map_err(|e| Error::NumberParse(e.to_string()))?
    };

    if negative {
        if magnitude > (i64::MAX as u128) + 1 {
            return Err(Error::NumberParse("value overflows i64".into()));
        }
        let signed = -(magnitude as i128);
        i64::try_from(signed).map_err(|_| Error::NumberParse("value overflows i64".into()))
    } else {
        i64::try_from(magnitude).map_err(|_| Error::NumberParse("value overflows i64".into()))
    }
}

/// Converts a `BigInt` to a secp256k1 `Scalar` if it fits in 32 bytes.
///
/// Returns `Some(Scalar)` if the BigInt is non-negative and fits within
/// 32 bytes. Returns `None` if the value is negative or too large.
///
/// # Arguments
///
/// * `d` - The BigInt to convert
///
/// # Returns
///
/// `Some(Scalar)` if conversion succeeds, `None` if the value is
/// negative or exceeds the scalar field size.
///
/// # Complexity
///
/// Linear in the serialized byte length of the integer.
///
/// # Example
///
/// ```
/// let bigint_val = BigInt::from(12345);
/// let scalar = bigint_to_scalar_opt(&bigint_val);
/// assert!(scalar.is_some());
/// ```
fn bigint_to_scalar_opt(d: &BigInt) -> Option<Scalar> {
    if d.is_negative() {
        return None;
    }
    let (_, bytes) = d.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_repr(arr.into()).into()
}

/// Resolves a report file path into the configured log directory.
///
/// Relative paths are written beneath the configured log directory.
/// The default search report name is made unique to avoid accidental
/// overwrites across multiple runs.
///
/// # Complexity
///
/// Constant time with respect to the path length, excluding the later
/// filesystem work needed to create parent directories or open the file.
///
/// # Arguments
///
/// * `requested_path` - The desired report file path
///
/// # Returns
///
/// A resolved path in the log directory, or the original absolute path.
///
/// # Example
///
/// ```
/// let path = resolve_report_path("search.log").unwrap();
/// assert!(path.ends_with("search.log"));
/// ```
fn resolve_report_path(requested_path: &str) -> Result<std::path::PathBuf> {
    let requested_path = requested_path.trim();
    if requested_path.is_empty() {
        return Err(Error::OutOfRange("outfile must not be empty".into()));
    }

    let requested = std::path::Path::new(requested_path);
    if requested.is_absolute() {
        return Ok(requested.to_path_buf());
    }

    if requested_path == "search.log" {
        let log_dir = logging::log_directory();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_secs(), d.subsec_nanos()))
            .unwrap_or((0, 0));
        let pid = std::process::id();
        let seq = LOG_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        return Ok(log_dir.join(format!("search_{}_{}_{}_{}.log", now.0, now.1, pid, seq)));
    }

    Ok(logging::resolve_report_path(requested_path)?)
}

/// Converts a `BigInt` to lowercase hex without a `0x` prefix.
///
/// # Arguments
///
/// * `x` - The BigInt to convert
///
/// # Returns
///
/// A lowercase hex string representation without "0x" prefix.
/// Returns "0" for zero values.
///
/// # Example
///
/// ```
/// let val = BigInt::from(255);
/// assert_eq!(bigint_to_lower_hex(&val), "ff");
/// ```
fn bigint_to_lower_hex(x: &BigInt) -> String {
    let (_, bytes) = x.to_bytes_be();
    if bytes.is_empty() {
        "0".into()
    } else {
        hex::encode(bytes)
    }
}

/// Converts a `Scalar` to lowercase hex without a `0x` prefix.
fn scalar_to_lower_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

// Unit tests for cryptographic functions
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Tests modular inverse computation.
    ///
    /// Verifies that a * a⁻¹ ≡ 1 (mod n) for a = 7.
    #[test]
    fn test_mod_inverse() {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();
        let a = BigInt::from(7u64);
        let inv = modular_inverse(&a, &n).unwrap();
        let prod = (a * inv) % &n;
        assert_eq!(prod, BigInt::one());
    }

    /// Tests that d = α·0 + β = β when delta = 0.
    #[test]
    fn test_precompute_and_private_key() {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();
        let r1 = BigInt::from(1u8);
        let r2 = BigInt::from(2u8);
        let s1 = BigInt::from(3u8);
        let s2 = BigInt::from(4u8);
        let z1 = BigInt::from(5u8);
        let z2 = BigInt::from(6u8);

        let (alpha, beta) = derive_affine_constants(&r1, &r2, &s1, &s2, &z1, &z2, &n).unwrap();
        let d0 = derive_private_key(
            0,
            bigint_to_scalar_opt(&alpha).unwrap(),
            bigint_to_scalar_opt(&beta).unwrap(),
        );
        assert_eq!(
            scalar_to_lower_hex(&d0),
            scalar_to_lower_hex(&bigint_to_scalar_opt(&beta).unwrap())
        );
    }

    /// Tests public key parsing and round-trip conversion.
    #[test]
    fn test_pubkey_conversion() {
        let pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk = parse_public_key(pk_hex).unwrap();
        let encoded = pk.to_encoded_point(true);
        assert_eq!(hex::encode(encoded.as_bytes()), pk_hex);
    }

    /// Tests hex string parsing with various formats.
    #[test]
    fn test_hex_parsing() {
        // With 0x prefix
        let val = parse_bigint_hex("0xFF").unwrap();
        assert_eq!(val, BigInt::from(255));

        // Without prefix
        let val2 = parse_bigint_hex("FF").unwrap();
        assert_eq!(val2, BigInt::from(255));

        // Odd-length padding
        let val3 = parse_bigint_hex("0xFFF").unwrap();
        let val4 = parse_bigint_hex("0x0FFF").unwrap();
        assert_eq!(val3, val4);
    }

    /// Tests range number parsing with decimal and hex.
    #[test]
    fn test_range_number_parsing() {
        assert_eq!(parse_bounded_integer("0").unwrap(), 0);
        assert_eq!(parse_bounded_integer("100").unwrap(), 100);
        assert_eq!(parse_bounded_integer("0xFF").unwrap(), 255);
        assert_eq!(parse_bounded_integer("0Xff").unwrap(), 255);
        assert_eq!(parse_bounded_integer("-0xFF").unwrap(), -255);
    }

    /// Tests the private-key candidate helper for negative deltas.
    #[test]
    fn test_private_key_candidate_signed_delta() {
        let alpha = Scalar::from(1u64);
        let beta = Scalar::from(2u64);
        let d = derive_private_key(-1, alpha, beta);
        assert_eq!(
            scalar_to_lower_hex(&d),
            scalar_to_lower_hex(&(beta - alpha))
        );
    }

    /// Tests normalize_modulo function with positive, negative, and boundary values.
    #[test]
    fn test_normalize() {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();

        // Positive value within range
        let val = BigInt::from(100);
        assert_eq!(normalize_modulo(&val, &n), val);

        // Negative value wraps to positive
        let neg_val = BigInt::from(-1);
        let result = normalize_modulo(&neg_val, &n);
        assert!(result > BigInt::zero());
        assert_eq!((result + BigInt::one()) % &n, BigInt::zero());

        // Zero normalizes to zero
        assert_eq!(normalize_modulo(&BigInt::zero(), &n), BigInt::zero());

        // Large negative value
        let large_neg = BigInt::from(-100);
        let result_large = normalize_modulo(&large_neg, &n);
        assert!(result_large >= BigInt::zero());
        assert!(result_large < n);
    }

    /// Tests bigint_to_scalar_opt with valid and invalid inputs.
    #[test]
    fn test_bigint_to_scalar() {
        // Valid small value
        let small = BigInt::from(42);
        assert!(bigint_to_scalar_opt(&small).is_some());

        // Valid max scalar value
        let max_scalar = BigInt::from_bytes_be(
            Sign::Plus,
            &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
                .unwrap(),
        );
        assert!(bigint_to_scalar_opt(&max_scalar).is_some());

        // Negative value returns None
        let neg = BigInt::from(-1);
        assert!(bigint_to_scalar_opt(&neg).is_none());

        // Value exceeding scalar range returns None
        let too_large = BigInt::from_bytes_be(
            Sign::Plus,
            &hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036414100")
                .unwrap(),
        );
        assert!(bigint_to_scalar_opt(&too_large).is_none());
    }

    /// Tests bigint_to_lower_hex with various inputs.
    #[test]
    fn test_hex_string() {
        // Zero returns empty-like representation
        let zero_str = bigint_to_lower_hex(&BigInt::zero());
        assert!(!zero_str.is_empty());

        // Normal value
        let val = BigInt::from(255);
        assert_eq!(bigint_to_lower_hex(&val), "ff");

        // Large value
        let large = parse_bigint_hex("0xDEADBEEF").unwrap();
        assert_eq!(bigint_to_lower_hex(&large), "deadbeef");
    }

    /// Tests unique_log_file_path generates timestamps for default path.
    #[test]
    fn test_unique_log_path() {
        // Default path gets timestamp
        let path = resolve_report_path("search.log").unwrap();
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("log"));
        assert_ne!(
            path.file_name().and_then(|name| name.to_str()),
            Some("search.log")
        );

        let next_path = resolve_report_path("search.log").unwrap();
        assert_ne!(path, next_path);

        // Custom relative path is resolved into the configured log directory.
        let custom = resolve_report_path("custom_output.log").unwrap();
        assert!(custom.ends_with("custom_output.log"));
    }

    /// Tests matches_target_public_key with matching and non-matching points.
    #[test]
    fn test_is_match() {
        // Use actual public key from test data
        let pk_hex = "03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f";
        let pk = parse_public_key(pk_hex).unwrap();
        let encoded = pk.to_encoded_point(true);
        let target_full = encoded.as_bytes();
        let target_x_bytes = &target_full[1..33];

        // Generate the matching point
        let d_scalar = Scalar::from(0x3039u64);
        let matching_point = ProjectivePoint::GENERATOR * d_scalar;

        // Should match
        assert!(matches_target_public_key(
            &matching_point,
            target_x_bytes,
            target_full
        ));

        // Generate a different point
        let wrong_point = ProjectivePoint::GENERATOR * Scalar::from(1u64);
        // Should not match (unless by extremely unlikely collision)
        assert!(!matches_target_public_key(
            &wrong_point,
            target_x_bytes,
            target_full
        ));
    }

    /// Tests that parse_public_key rejects invalid formats.
    #[test]
    fn test_parse_pubkey_invalid_formats() {
        // Empty string
        assert!(parse_public_key("").is_err());

        // Invalid hex (contains non-hex chars)
        assert!(parse_public_key("0xgg").is_err());

        // Single byte prefix only
        assert!(parse_public_key("01").is_err());

        // Too short for 02/03 (need 33 bytes = 66 hex chars)
        let short_hex = "02".to_string() + &"ff".repeat(31);
        assert!(parse_public_key(&short_hex).is_err());

        // Too short for 04 (need 65 bytes = 130 hex chars)
        let short_uncompressed = "04".to_string() + &"ff".repeat(31);
        assert!(parse_public_key(&short_uncompressed).is_err());

        // Valid compressed key works (66 hex chars)
        let compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(parse_public_key(compressed).is_ok());

        // Valid uncompressed key works (130 hex chars)
        let uncompressed = concat!(
            "04",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        );
        assert!(parse_public_key(uncompressed).is_ok());

        // Invalid uncompressed point is rejected even if the length looks correct.
        let invalid_uncompressed = concat!(
            "04",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9",
        );
        assert!(parse_public_key(invalid_uncompressed).is_err());
    }

    /// Tests modular_inverse with known values.
    #[test]
    fn test_mod_inverse_specific() {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();

        // Inverse of 1 is 1
        let inv1 = modular_inverse(&BigInt::one(), &n).unwrap();
        assert_eq!(inv1, BigInt::one());

        // Inverse of 2
        let inv2 = modular_inverse(&BigInt::from(2), &n).unwrap();
        let prod2 = (BigInt::from(2) * &inv2) % &n;
        assert_eq!(prod2, BigInt::one());

        // No inverse exists when gcd(a, n) != 1
        // n itself has no inverse (gcd(n, n) = n)
        let result_n = modular_inverse(&n, &n);
        assert!(result_n.is_err());
    }

    /// Tests derive_affine_constants with zero values (edge case).
    #[test]
    fn test_precompute_edge_cases() {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();

        // Using simple values that won't cause modular inverse issues
        let r1 = BigInt::from(1u8);
        let r2 = BigInt::from(2u8);
        let s1 = BigInt::from(1u8);
        let s2 = BigInt::from(1u8);
        let z1 = BigInt::from(0u8);
        let z2 = BigInt::from(0u8);

        // This should work mathematically
        let result = derive_affine_constants(&r1, &r2, &s1, &s2, &z1, &z2, &n);
        assert!(result.is_ok());
    }

    /// Tests that the search recovers a negative delta when it lies inside the bounded range.
    #[test]
    fn test_search_finds_negative_delta() {
        let (r1, r2, s1, s2, z1, z2, pk, n) = negative_delta_fixture();
        let outfile = temp_log_path("negative_delta_found");

        search(
            r1, r2, s1, s2, z1, z2, pk, -2, 0, 1, None, true, &outfile, &n,
        )
        .unwrap();

        let log = std::fs::read_to_string(&outfile).unwrap();
        assert!(log.contains("FOUND delta=-1"));
        let expected_d = Scalar::from(0x3039u64);
        assert!(log.contains(&format!("d=0x{}", scalar_to_lower_hex(&expected_d))));
        let _ = std::fs::remove_file(&outfile);
    }

    /// Tests that the search reports no match when the true delta is outside the bounded range.
    #[test]
    fn test_search_reports_no_match_outside_range() {
        let (r1, r2, s1, s2, z1, z2, pk, n) = negative_delta_fixture();
        let outfile = temp_log_path("negative_delta_miss");

        search(
            r1, r2, s1, s2, z1, z2, pk, 0, 0, 1, None, true, &outfile, &n,
        )
        .unwrap();

        let log = std::fs::read_to_string(&outfile).unwrap();
        assert!(log.contains("No key found in searched range."));
        let _ = std::fs::remove_file(&outfile);
    }

    /// Tests that an empty output path is rejected before file creation.
    #[test]
    fn test_search_rejects_empty_outfile() {
        let (r1, r2, s1, s2, z1, z2, pk, n) = negative_delta_fixture();
        let err = search(r1, r2, s1, s2, z1, z2, pk, -2, 0, 1, None, true, "   ", &n)
            .expect_err("empty outfile must be rejected");

        match err {
            Error::OutOfRange(msg) => assert!(msg.contains("outfile")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn negative_delta_fixture() -> (
        BigInt,
        BigInt,
        BigInt,
        BigInt,
        BigInt,
        BigInt,
        PublicKey,
        BigInt,
    ) {
        let n = parse_bigint_hex(CURVE_ORDER_HEX).unwrap();
        let private_key_scalar = Scalar::from(0x3039u64);
        let nonce = 0x1234u64;
        let delta = -1i64;
        let next_nonce = nonce
            .checked_add_signed(delta)
            .expect("fixture delta must keep nonce positive");

        let r1 = r_value_from_nonce(nonce, &n);
        let r2 = r_value_from_nonce(next_nonce, &n);
        let r1_scalar = bigint_to_scalar_opt(&r1).unwrap();
        let r2_scalar = bigint_to_scalar_opt(&r2).unwrap();

        let z1 = BigInt::from(1u8);
        let z2 = BigInt::from(2u8);
        let s1_scalar = (Scalar::from(1u64) + r1_scalar * private_key_scalar)
            * Scalar::from(nonce).invert().unwrap();
        let s2_scalar = (Scalar::from(2u64) + r2_scalar * private_key_scalar)
            * Scalar::from(next_nonce).invert().unwrap();
        let s1 = bigint_from_scalar(s1_scalar);
        let s2 = bigint_from_scalar(s2_scalar);

        let public_key_point = ProjectivePoint::GENERATOR * private_key_scalar;
        let public_key = PublicKey::from_sec1_bytes(
            public_key_point
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();

        (r1, r2, s1, s2, z1, z2, public_key, n)
    }

    fn r_value_from_nonce(nonce: u64, curve_order: &BigInt) -> BigInt {
        let point = ProjectivePoint::GENERATOR * Scalar::from(nonce);
        let encoded = point.to_affine().to_encoded_point(true);
        let x = BigInt::from_bytes_be(Sign::Plus, &encoded.as_bytes()[1..33]);
        normalize_modulo(&x, curve_order)
    }

    fn bigint_from_scalar(scalar: Scalar) -> BigInt {
        BigInt::from_bytes_be(Sign::Plus, &scalar.to_bytes())
    }

    fn temp_log_path(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("{prefix}_{}_{}.log", std::process::id(), nanos))
            .to_string_lossy()
            .into_owned()
    }
}
