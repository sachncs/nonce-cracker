//! CLI argument parsing and command dispatch.
//!
//! This module contains the `clap` derive macros, search orchestration,
//! and output formatting.  The [`main`] entry point in `main.rs` calls
//! [`run_search`] or [`run_example`] after initialising logging and
//! configuration.

use clap::{Args, Parser, Subcommand};
use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
use k256::{ProjectivePoint, PublicKey, Scalar};
use nonce_cracker::{
    derive_private_key, logging::emit_summary, parse_int, parse_pubkey, parse_scalar, scalar_hex,
    verify_ecdsa_signature, AppContext, CryptoError, Error, RangeError, Result, SearchEngine,
    SearchOutcome, SearchSpec, Signature,
};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Level;
use zeroize::Zeroize;

/// Top-level CLI parsed by `clap`.
#[derive(Parser, Debug)]
#[command(
    name = "nonce-cracker",
    author,
    version,
    about = "High-speed parallel ECDSA key search for secp256k1"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Arguments for the `run` subcommand.
///
/// Signature values are given as (r, s, z).
#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Signature R coordinate.
    #[arg(long)]
    pub r: String,
    /// Signature S value.
    #[arg(long)]
    pub s: String,
    /// Message hash (z).
    #[arg(long)]
    pub z: String,
    /// Target public key (compressed or uncompressed).
    #[arg(long)]
    pub pubkey: String,
    /// Search range start (decimal or `0x` hex).
    #[arg(long, default_value = "0", allow_hyphen_values = true)]
    pub start: String,
    /// Search range end (decimal or `0x` hex).
    #[arg(long, default_value = "0x1000000000000000", allow_hyphen_values = true)]
    pub end: String,
    /// Step between candidates.
    #[arg(long, default_value = "1", allow_hyphen_values = true)]
    pub step: String,
    /// Number of worker threads (`None` = auto-detect).
    #[arg(long)]
    pub threads: Option<usize>,
    /// Suppress console output.
    #[arg(long, default_value = "false")]
    pub quiet: bool,
    /// Report file name or path.
    #[arg(long, default_value = "search.log")]
    pub outfile: String,
    /// Offset to subtract from the private key before searching.
    ///
    /// The search uses `d_new = alpha * k` where `d_new = d - offset`.
    /// When a nonce is found, the recovered private key is `d = alpha * k + offset`.
    #[arg(long, default_value = "0", allow_hyphen_values = true)]
    pub offset: String,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Search for a private key given a single ECDSA signature.
    #[command(name = "run")]
    Search(Box<SearchArgs>),
    /// Run the built-in demonstration.
    #[command(name = "example")]
    Example,
}

/// Execute a search using the provided CLI arguments.
pub fn run_search(ctx: &AppContext, args: &SearchArgs) -> Result<()> {
    if args.outfile.trim().is_empty() {
        return Err(Error::Range(RangeError::EmptyOutfile));
    }
    if matches!(args.threads, Some(0)) {
        return Err(Error::Range(RangeError::ThreadsNotPositive));
    }

    let sig = Signature::new(
        parse_scalar(&args.r)?,
        parse_scalar(&args.s)?,
        parse_scalar(&args.z)?,
    );
    let target = parse_pubkey(&args.pubkey)?;
    verify_ecdsa_signature(&target, &sig.r, &sig.s, &sig.z)?;

    let offset = parse_scalar(&args.offset)?;

    let (search_target, search_sig, d_offset) = if offset == k256::Scalar::ZERO {
        (target, sig, None)
    } else {
        // Offset mode: search for d_new = alpha * k where d_new = d - offset.
        // Adjust target: Q_new = Q - offset * G.
        // Use z=0 signature so beta=0 in the search.
        let offset_point = k256::ProjectivePoint::GENERATOR * offset;
        let target_affine: k256::AffinePoint = *target.as_affine();
        let adjusted: k256::AffinePoint =
            (k256::ProjectivePoint::from(target_affine) - offset_point).to_affine();
        let adjusted_pk =
            k256::PublicKey::from_affine(adjusted).map_err(|e| {
                CryptoError::PubkeyParse(format!("adjusted target public key: {e}"))
            })?;
        let search_sig = Signature::new(sig.r, sig.s, k256::Scalar::ZERO);
        (adjusted_pk, search_sig, Some(offset))
    };

    let spec = SearchSpec::new(
        parse_int(&args.start)?,
        parse_int(&args.end)?,
        parse_int(&args.step)?,
    )?;

    let engine = SearchEngine::new(&ctx.config, args.threads, ctx.shutdown.clone())?;

    let out = resolve_path(&ctx.config.log_dir, &args.outfile)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = out.with_extension(format!("tmp.{}", std::process::id()));
    let mut log = BufWriter::new(File::create(&tmp)?);

    let outcome = engine.search(&spec, &search_sig, &search_target)?;

    write_outcome(&mut log, &outcome, !args.quiet, d_offset.as_ref())?;
    drop(log);
    std::fs::rename(&tmp, &out)?;
    Ok(())
}

/// Run the built-in demonstration with a hard-coded single signature.
pub fn run_example(ctx: &AppContext) -> Result<()> {
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
    verify_ecdsa_signature(&pk, &r, &s, &z)?;

    let sig = Signature::new(r, s, z);
    let spec = SearchSpec::new(0, 0x2000, 1)?;

    let engine = SearchEngine::new(&ctx.config, None, ctx.shutdown.clone())?;

    let out = resolve_path(&ctx.config.log_dir, "example.log")?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = out.with_extension(format!("tmp.{}", std::process::id()));
    let mut log = BufWriter::new(File::create(&tmp)?);

    let outcome = engine.search(&spec, &sig, &pk)?;

    write_outcome(&mut log, &outcome, true, None)?;
    drop(log);
    std::fs::rename(&tmp, &out)?;
    Ok(())
}

/// Write the search outcome to the log file and optionally the console.
///
/// If `offset` is provided, it is added to the derived private key before
/// reporting (offset-search mode).
fn write_outcome(
    log: &mut BufWriter<File>,
    outcome: &SearchOutcome,
    console: bool,
    offset: Option<&k256::Scalar>,
) -> Result<()> {
    writeln!(log, "alpha: 0x{}", scalar_hex(&outcome.alpha))?;
    writeln!(log, "beta:  0x{}", scalar_hex(&outcome.beta))?;

    if let Some(nonce) = outcome.nonce {
        let mut d = derive_private_key(nonce.unsigned_abs(), outcome.alpha, outcome.beta);
        if let Some(off) = offset {
            d += *off;
        }
        let hex = scalar_hex(&d);
        writeln!(log, "FOUND nonce={nonce} d=0x{hex}")?;
        emit_summary(
            Level::INFO,
            format!("event=search_result status=found nonce={nonce} d=0x{hex}"),
            console,
        );
        d.zeroize();
    } else {
        writeln!(log, "No key found in searched range.")?;
        emit_summary(Level::WARN, "event=search_result status=missing", console);
    }
    log.flush()?;
    Ok(())
}

/// Resolve an outfile path relative to the configured log directory.
///
/// - Absolute paths are returned as-is.
/// - The literal value `"search.log"` is expanded to a unique filename
///   incorporating the current time and PID to avoid collisions.
/// - Any other relative path is resolved under `base_dir`.
pub fn resolve_path(base_dir: &Path, p: &str) -> Result<std::path::PathBuf> {
    let p = p.trim();
    if p.is_empty() {
        return Err(Error::Range(RangeError::EmptyOutfile));
    }
    let path = std::path::Path::new(p);
    if path.is_absolute() || p.starts_with('/') {
        return Ok(path.to_path_buf());
    }
    if p == "search.log" {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        return Ok(base_dir.join(format!("search_{nanos}_{}.log", std::process::id())));
    }
    Ok(base_dir.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{sec1::ToEncodedPoint, PrimeField};
    use k256::{ProjectivePoint, PublicKey, Scalar};
    use nonce_cracker::Config;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_unique_log_path() {
        let base = std::env::temp_dir();
        let p1 = resolve_path(&base, "search.log").unwrap();
        let p2 = resolve_path(&base, "search.log").unwrap();
        assert_ne!(p1, p2);
        assert!(resolve_path(&base, "custom.log")
            .unwrap()
            .ends_with("custom.log"));
    }

    #[test]
    fn test_match() {
        let pk = parse_pubkey("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
            .unwrap();
        let target: k256::AffinePoint = *pk.as_affine();
        let matching = ProjectivePoint::GENERATOR * Scalar::from(0x3039u64);
        let wrong = ProjectivePoint::GENERATOR * Scalar::from(1u64);
        assert!(matching == target);
        assert!(wrong != target);
    }

    #[test]
    fn test_search_found_nonce() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            checkpoint_dir: std::env::temp_dir().join("checkpoints"),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (sig, pk) = fixture();
        let out = temp_log("nonce_found");
        let spec = SearchSpec::new(0, 0x2000, 1).unwrap();
        let engine = SearchEngine::new(
            &ctx.config,
            None,
            ctx.shutdown.clone(),
        )
        .unwrap();
        let outcome = engine.search(&spec, &sig, &pk).unwrap();
        assert_eq!(outcome.nonce, Some(0x1234));

        let mut log = BufWriter::new(File::create(&out).unwrap());
        write_outcome(&mut log, &outcome, false, None).unwrap();
        let log = std::fs::read_to_string(&out).unwrap();
        assert!(log.contains("FOUND nonce=4660")); // 0x1234 = 4660
        assert!(log.contains(&format!("d=0x{}", scalar_hex(&Scalar::from(0x3039u64)))));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_search_no_match() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            checkpoint_dir: std::env::temp_dir().join("checkpoints"),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (sig, pk) = fixture();
        let out = temp_log("nonce_miss");
        let spec = SearchSpec::new(0, 0, 1).unwrap();
        let engine = SearchEngine::new(
            &ctx.config,
            None,
            ctx.shutdown.clone(),
        )
        .unwrap();
        let outcome = engine.search(&spec, &sig, &pk).unwrap();
        assert_eq!(outcome.nonce, None);

        let mut log = BufWriter::new(File::create(&out).unwrap());
        write_outcome(&mut log, &outcome, false, None).unwrap();
        assert!(std::fs::read_to_string(&out)
            .unwrap()
            .contains("No key found"));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_empty_outfile() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            checkpoint_dir: std::env::temp_dir().join("checkpoints"),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (sig, pk) = fixture();
        let err = run_search(
            &ctx,
            &SearchArgs {
                r: scalar_to_hex(&sig.r),
                s: scalar_to_hex(&sig.s),
                z: scalar_to_hex(&sig.z),
                pubkey: hex::encode(pk.to_encoded_point(true).as_bytes()),
                start: "0".into(),
                end: "10".into(),
                step: "1".into(),
                threads: None,
                quiet: true,
                outfile: "   ".into(),
                offset: "0".into(),
            },
        )
        .expect_err("should reject empty");
        assert!(err.to_string().contains("outfile"));
    }

    fn fixture() -> (Signature, PublicKey) {
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

        (Signature::new(r, s, z), pk)
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

    fn scalar_to_hex(s: &Scalar) -> String {
        format!("0x{}", hex::encode(s.to_bytes()))
    }

    #[test]
    fn test_resolve_path_absolute() {
        let base = std::env::temp_dir();
        let abs = std::path::PathBuf::from("/absolute/path.log");
        let resolved = resolve_path(&base, "/absolute/path.log").unwrap();
        assert_eq!(resolved, abs);
    }

    #[test]
    fn test_resolve_path_empty() {
        let base = std::env::temp_dir();
        let err = resolve_path(&base, "   ").unwrap_err();
        assert!(err.to_string().contains("outfile"));
    }

    #[test]
    fn test_run_search_threads_zero() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            checkpoint_dir: std::env::temp_dir().join("checkpoints"),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (sig, pk) = fixture();
        let err = run_search(
            &ctx,
            &SearchArgs {
                r: scalar_to_hex(&sig.r),
                s: scalar_to_hex(&sig.s),
                z: scalar_to_hex(&sig.z),
                pubkey: hex::encode(pk.to_encoded_point(true).as_bytes()),
                start: "0".into(),
                end: "10".into(),
                step: "1".into(),
                threads: Some(0),
                quiet: true,
                outfile: "test.log".into(),
                offset: "0".into(),
            },
        )
        .expect_err("should reject zero threads");
        assert!(err.to_string().contains("threads"));
    }
}
