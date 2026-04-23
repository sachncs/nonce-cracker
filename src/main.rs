use crate::crypto::{
    derive_affine_constants, derive_private_key, parse_int, parse_pubkey, parse_scalar, scalar_hex,
};
use crate::search::{bsgs, parallel_scan, set_shutdown, BSGS_THRESHOLD};
use clap::{Parser, Subcommand};
use k256::{AffinePoint, ProjectivePoint, PublicKey, Scalar};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn, Level};

mod config;
mod crypto;
mod logging;
mod metrics;
mod search;

#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Self(format!("hex parse error: {e}"))
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Self(format!("number parse error: {e}"))
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self(format!("io error: {e}"))
    }
}
impl From<logging::LoggingError> for Error {
    fn from(e: logging::LoggingError) -> Self {
        Self(format!("logging error: {e}"))
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Parser, Debug)]
#[command(
    name = "nonce-cracker",
    author,
    version,
    about = "High-speed parallel ECDSA key search for secp256k1"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(name = "run")]
    Search {
        #[arg(long)]
        r1: String,
        #[arg(long)]
        r2: String,
        #[arg(long)]
        s1: String,
        #[arg(long)]
        s2: String,
        #[arg(long)]
        z1: String,
        #[arg(long)]
        z2: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long, default_value = "0", allow_hyphen_values = true)]
        start: String,
        #[arg(long, default_value = "0x1000000000000000", allow_hyphen_values = true)]
        end: String,
        #[arg(long, default_value = "1", allow_hyphen_values = true)]
        step: String,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long, default_value = "false")]
        quiet: bool,
        #[arg(long, default_value = "search.log")]
        outfile: String,
    },
    #[command(name = "example")]
    Example,
}

fn main() {
    if let Err(e) = config::Config::init() {
        eprintln!("config: {e}");
        std::process::exit(1);
    }
    if let Err(e) = logging::init() {
        eprintln!("logging: {e}");
        std::process::exit(1);
    }

    #[cfg(unix)]
    {
        std::thread::spawn(|| {
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ])
            .expect("signals");
            for sig in signals.forever() {
                if sig == signal_hook::consts::SIGINT || sig == signal_hook::consts::SIGTERM {
                    info!(signal = sig, "shutdown signal received");
                    set_shutdown();
                    break;
                }
            }
        });
    }

    info!(version = config::Config::get().version, "starting");

    let cli = Cli::parse();
    let code = match cli.command.unwrap_or(Commands::Example) {
        Commands::Example => run_example().map(|_| 0).unwrap_or_else(|e| {
            error!("example failed: {e}");
            1
        }),
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
        } => run_search(
            r1, r2, s1, s2, z1, z2, pubkey, start, end, step, threads, quiet, outfile,
        )
        .map(|_| 0)
        .unwrap_or_else(|e| {
            error!("search failed: {e}");
            1
        }),
    };

    info!("shutting down");
    std::process::exit(code);
}

fn run_search(
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
) -> Result<()> {
    let r1 = parse_scalar(&r1)?;
    let r2 = parse_scalar(&r2)?;
    let s1 = parse_scalar(&s1)?;
    let s2 = parse_scalar(&s2)?;
    let z1 = parse_scalar(&z1)?;
    let z2 = parse_scalar(&z2)?;
    let pk = parse_pubkey(&pubkey)?;
    let start = parse_int(&start)?;
    let end = parse_int(&end)?;
    let step = parse_int(&step)?;
    if step == 0 {
        return Err(Error("step must be > 0".into()));
    }
    search(
        r1, r2, s1, s2, z1, z2, pk, start, end, step, threads, quiet, &outfile,
    )
}

fn run_example() -> Result<()> {
    let r1 = parse_scalar("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba")?;
    let s1 = parse_scalar("0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8")?;
    let z1 = parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000001")?;
    let r2 = parse_scalar("0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12")?;
    let s2 = parse_scalar("0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7")?;
    let z2 = parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000002")?;
    let pk = parse_pubkey("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")?;
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
    )
}

#[allow(clippy::too_many_arguments)]
fn search(
    r1: Scalar,
    r2: Scalar,
    s1: Scalar,
    s2: Scalar,
    z1: Scalar,
    z2: Scalar,
    target: PublicKey,
    start: i64,
    end: i64,
    step: i64,
    threads: Option<usize>,
    quiet: bool,
    outfile: &str,
) -> Result<()> {
    if end < start {
        return Err(Error("end must be >= start".into()));
    }
    if matches!(threads, Some(0)) {
        return Err(Error("threads must be > 0".into()));
    }
    if outfile.trim().is_empty() {
        return Err(Error("outfile must not be empty".into()));
    }
    if step <= 0 {
        return Err(Error("step must be > 0".into()));
    }

    let max_threads = config::Config::get().max_threads;
    let thread_count = match threads {
        Some(t) if t > max_threads => {
            warn!(requested = t, max = max_threads, "capping threads");
            max_threads
        }
        Some(t) => t,
        None => std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1)
            .min(max_threads),
    };

    let (alpha, beta) = derive_affine_constants(r1, r2, s1, s2, z1, z2)?;

    let out = resolve_path(outfile)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = BufWriter::new(File::create(&out)?);
    writeln!(log, "alpha: 0x{}", scalar_hex(&alpha))?;
    writeln!(log, "beta:  0x{}", scalar_hex(&beta))?;

    let step_scalar = alpha * Scalar::from(step.unsigned_abs());
    let step_point = ProjectivePoint::GENERATOR * step_scalar;
    let target_affine: AffinePoint = *target.as_affine();

    let span = (end as i128)
        .checked_sub(start as i128)
        .ok_or_else(|| Error("range overflow".into()))?;
    let step_i128 = step as i128;
    let total: u128 = (span / step_i128 + 1)
        .try_into()
        .map_err(|_| Error("range too large".into()))?;

    if step_scalar == Scalar::from(0u64) {
        let d0 = derive_private_key(start, alpha, beta);
        let point = ProjectivePoint::GENERATOR * d0;
        if point == target_affine {
            let hex = scalar_hex(&d0);
            writeln!(log, "FOUND delta={start} d=0x{hex}")?;
            logging::emit_summary(
                Level::INFO,
                format!(
                    "event=search_result status=found delta={start} d=0x{hex} report={}",
                    out.display()
                ),
                !quiet,
            );
        } else {
            writeln!(log, "No key found in searched range.")?;
            logging::emit_summary(
                Level::WARN,
                format!(
                    "event=search_result status=missing report={}",
                    out.display()
                ),
                !quiet,
            );
        }
        return Ok(());
    }

    info!(
        search_start = start,
        search_end = end,
        step = step,
        threads = thread_count,
        total = total,
        "starting search"
    );
    let m = metrics::search_started(thread_count);

    let found = if total <= BSGS_THRESHOLD {
        parallel_scan(
            target,
            start,
            step,
            total,
            thread_count,
            alpha,
            beta,
            step_point,
        )?
    } else {
        bsgs(
            target,
            start,
            step,
            total,
            thread_count,
            alpha,
            beta,
            step_point,
        )?
    };

    if let Some(found_delta) = found {
        let d = derive_private_key(found_delta, alpha, beta);
        let hex = scalar_hex(&d);
        writeln!(log, "FOUND delta={found_delta} d=0x{hex}")?;
        metrics::search_completed(&m, true, Some(found_delta));
        logging::emit_summary(
            Level::INFO,
            format!(
                "event=search_result status=found delta={found_delta} d=0x{hex} report={}",
                out.display()
            ),
            !quiet,
        );
    } else {
        writeln!(log, "No key found in searched range.")?;
        metrics::search_completed(&m, false, None);
        logging::emit_summary(
            Level::WARN,
            format!(
                "event=search_result status=missing report={}",
                out.display()
            ),
            !quiet,
        );
    }

    Ok(())
}

fn resolve_path(p: &str) -> Result<PathBuf> {
    let p = p.trim();
    if p.is_empty() {
        return Err(Error("outfile must not be empty".into()));
    }
    let path = std::path::Path::new(p);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if p == "search.log" {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        return Ok(logging::log_dir().join(format!("search_{nanos}_{}.log", std::process::id())));
    }
    Ok(logging::log_dir().join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_unique_log_path() {
        let p1 = resolve_path("search.log").unwrap();
        let p2 = resolve_path("search.log").unwrap();
        assert_ne!(p1, p2);
        assert!(resolve_path("custom.log").unwrap().ends_with("custom.log"));
    }

    #[test]
    fn test_match() {
        let pk = parse_pubkey("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
            .unwrap();
        let target: AffinePoint = *pk.as_affine();
        let matching = ProjectivePoint::GENERATOR * Scalar::from(0x3039u64);
        let wrong = ProjectivePoint::GENERATOR * Scalar::from(1u64);
        assert!(matching == target);
        assert!(wrong != target);
    }

    #[test]
    fn test_search_negative_delta() {
        let (r1, r2, s1, s2, z1, z2, pk) = fixture();
        let out = temp_log("neg_delta_found");
        search(r1, r2, s1, s2, z1, z2, pk, -2, 0, 1, None, true, &out).unwrap();
        let log = std::fs::read_to_string(&out).unwrap();
        assert!(log.contains("FOUND delta=-1"));
        assert!(log.contains(&format!("d=0x{}", scalar_hex(&Scalar::from(0x3039u64)))));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_search_no_match() {
        let (r1, r2, s1, s2, z1, z2, pk) = fixture();
        let out = temp_log("neg_delta_miss");
        search(r1, r2, s1, s2, z1, z2, pk, 0, 0, 1, None, true, &out).unwrap();
        assert!(std::fs::read_to_string(&out)
            .unwrap()
            .contains("No key found"));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_empty_outfile() {
        let (r1, r2, s1, s2, z1, z2, pk) = fixture();
        let err = search(r1, r2, s1, s2, z1, z2, pk, -2, 0, 1, None, true, "   ")
            .expect_err("should reject empty");
        assert!(err.to_string().contains("outfile"));
    }

    #[test]
    fn test_step_scalar_zero() {
        // When alpha = 0, all candidates evaluate to the same private key.
        // The search should short-circuit after checking the first candidate.
        let pk = PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * Scalar::from(0x3039u64))
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        let r1 = Scalar::from(1u64);
        let r2 = Scalar::from(1u64);
        let s1 = Scalar::from(1u64);
        let s2 = Scalar::from(0u64);
        let z1 = Scalar::from(0u64);
        let z2 = Scalar::from(0u64) - Scalar::from(0x3039u64);

        let out = temp_log("step_zero");
        search(r1, r2, s1, s2, z1, z2, pk, 0, 10, 1, None, true, &out).unwrap();
        let log = std::fs::read_to_string(&out).unwrap();
        assert!(log.contains("FOUND delta=0"));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_bsgs_small_range() {
        let (r1, r2, s1, s2, z1, z2, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        let found = bsgs(pk, -10, 1, 21, 4, alpha, beta, step_point).unwrap();
        assert_eq!(found, Some(-1));
    }

    #[test]
    fn test_bsgs_medium_range() {
        let (r1, r2, s1, s2, z1, z2, pk) = fixture();
        let (alpha, beta) = derive_affine_constants(r1, r2, s1, s2, z1, z2).unwrap();
        let step_point = ProjectivePoint::GENERATOR * (alpha * Scalar::from(1u64));
        // N = 201, expected at delta = -1
        let found = bsgs(pk, -100, 1, 201, 4, alpha, beta, step_point).unwrap();
        assert_eq!(found, Some(-1));
    }

    fn fixture() -> (Scalar, Scalar, Scalar, Scalar, Scalar, Scalar, PublicKey) {
        let d = Scalar::from(0x3039u64);
        let nonce = 0x1234u64;
        let next = nonce - 1;

        let r1 = r_from_nonce(nonce);
        let r2 = r_from_nonce(next);
        let z1 = Scalar::from(1u64);
        let z2 = Scalar::from(2u64);
        let s1 = sig_s(1, r1, d, nonce);
        let s2 = sig_s(2, r2, d, next);

        let pk = PublicKey::from_sec1_bytes(
            (ProjectivePoint::GENERATOR * d)
                .to_affine()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();

        (r1, r2, s1, s2, z1, z2, pk)
    }

    fn r_from_nonce(n: u64) -> Scalar {
        let enc = (ProjectivePoint::GENERATOR * Scalar::from(n))
            .to_affine()
            .to_encoded_point(true);
        let mut b = [0u8; 32];
        b.copy_from_slice(&enc.as_bytes()[1..33]);
        Scalar::from_repr(b.into()).unwrap()
    }

    fn sig_s(z: u64, r: Scalar, d: Scalar, nonce: u64) -> Scalar {
        (Scalar::from(z) + r * d) * Scalar::from(nonce).invert().unwrap()
    }

    fn temp_log(prefix: &str) -> String {
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
