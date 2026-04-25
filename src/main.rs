use clap::{Args, Parser, Subcommand};
use nonce_cracker::{
    derive_private_key, emit_summary, init_logging, parse_int, parse_pubkey, parse_scalar,
    scalar_hex, AppContext, Config, Error, RangeError, Result, SearchEngine, SearchOutcome,
    SearchSpec, Signature, SignaturePair, TracingMetricsSink,
};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, Level};

/// Top-level CLI parsed by `clap`.
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

/// Arguments for the `run` subcommand.
///
/// Signature values are given in ECDSA order (r1, r2, s1, s2, z1, z2).
#[derive(Args, Debug)]
struct SearchArgs {
    /// First signature R coordinate.
    #[arg(long)]
    r1: String,
    /// Second signature R coordinate.
    #[arg(long)]
    r2: String,
    /// First signature S value.
    #[arg(long)]
    s1: String,
    /// Second signature S value.
    #[arg(long)]
    s2: String,
    /// First message hash.
    #[arg(long)]
    z1: String,
    /// Second message hash.
    #[arg(long)]
    z2: String,
    /// Target public key (compressed or uncompressed).
    #[arg(long)]
    pubkey: String,
    /// Search range start (decimal or `0x` hex).
    #[arg(long, default_value = "0", allow_hyphen_values = true)]
    start: String,
    /// Search range end (decimal or `0x` hex).
    #[arg(long, default_value = "0x1000000000000000", allow_hyphen_values = true)]
    end: String,
    /// Step between candidates.
    #[arg(long, default_value = "1", allow_hyphen_values = true)]
    step: String,
    /// Number of worker threads (`None` = auto-detect).
    #[arg(long)]
    threads: Option<usize>,
    /// Suppress console output.
    #[arg(long, default_value = "false")]
    quiet: bool,
    /// Report file name or path.
    #[arg(long, default_value = "search.log")]
    outfile: String,
}

/// Available CLI subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Search for a private key given two ECDSA signatures.
    #[command(name = "run")]
    Search(Box<SearchArgs>),
    /// Run the built-in demonstration.
    #[command(name = "example")]
    Example,
}

fn main() {
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            std::process::exit(1);
        }
    };

    let console = std::env::var("NONCE_CRACKER_LOG_CONSOLE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(true);

    if let Err(e) = init_logging(&config.log_dir, console) {
        eprintln!("logging: {e}");
        std::process::exit(1);
    }

    let ctx = AppContext::new(config);

    #[cfg(unix)]
    {
        let shutdown = ctx.shutdown.clone();
        std::thread::spawn(move || {
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ])
            .expect("signals");
            for sig in signals.forever() {
                if sig == signal_hook::consts::SIGINT || sig == signal_hook::consts::SIGTERM {
                    info!(signal = sig, "shutdown signal received");
                    shutdown.signal();
                    break;
                }
            }
        });
    }

    info!(version = ctx.config.version, "starting");

    let cli = Cli::parse();
    let code = match cli.command.unwrap_or(Commands::Example) {
        Commands::Example => run_example(&ctx).map_or_else(
            |e| {
                error!("example failed: {e}");
                1
            },
            |()| 0,
        ),
        Commands::Search(args) => run_search(&ctx, &args).map_or_else(
            |e| {
                error!("search failed: {e}");
                1
            },
            |()| 0,
        ),
    };

    info!("shutting down");
    std::process::exit(code);
}

fn run_search(ctx: &AppContext, args: &SearchArgs) -> Result<()> {
    if args.outfile.trim().is_empty() {
        return Err(Error::Range(RangeError::EmptyOutfile));
    }
    if matches!(args.threads, Some(0)) {
        return Err(Error::Range(RangeError::ThreadsNotPositive));
    }

    let sig1 = Signature::new(
        parse_scalar(&args.r1)?,
        parse_scalar(&args.s1)?,
        parse_scalar(&args.z1)?,
    );
    let sig2 = Signature::new(
        parse_scalar(&args.r2)?,
        parse_scalar(&args.s2)?,
        parse_scalar(&args.z2)?,
    );
    let pair = SignaturePair::new(sig1, sig2);
    let target = parse_pubkey(&args.pubkey)?;
    let spec = SearchSpec::new(
        parse_int(&args.start)?,
        parse_int(&args.end)?,
        parse_int(&args.step)?,
    )?;

    let engine = SearchEngine::new(
        &ctx.config,
        args.threads,
        ctx.shutdown.clone(),
        Arc::new(TracingMetricsSink),
    )?;

    let out = resolve_path(&ctx.config.log_dir, &args.outfile)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = BufWriter::new(File::create(&out)?);

    let outcome = engine.search(&spec, &pair, &target)?;

    write_outcome(&mut log, &outcome, !args.quiet)?;
    Ok(())
}

fn run_example(ctx: &AppContext) -> Result<()> {
    let r1 = parse_scalar("0x37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba")?;
    let s1 = parse_scalar("0xe026eb94e61bcdc41f0ee8cd7b97eda899ce5856d3a32360d742b13d717ff2a8")?;
    let z1 = parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000001")?;
    let r2 = parse_scalar("0xba5aec8a54a3a56fcd1bf17bceba9c4fad7103abf06669748b66578d03e0de12")?;
    let s2 = parse_scalar("0x31bc5dd7d522300c1a3fa117322581571329a2af3ba0d1a9b72d3c36eeac3ec7")?;
    let z2 = parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000002")?;
    let pk = parse_pubkey("03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")?;

    let pair = SignaturePair::new(Signature::new(r1, s1, z1), Signature::new(r2, s2, z2));
    let spec = SearchSpec::new(0, 2, 1)?;

    let engine = SearchEngine::new(
        &ctx.config,
        None,
        ctx.shutdown.clone(),
        Arc::new(TracingMetricsSink),
    )?;

    let out = resolve_path(&ctx.config.log_dir, "example.log")?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = BufWriter::new(File::create(&out)?);

    let outcome = engine.search(&spec, &pair, &pk)?;

    write_outcome(&mut log, &outcome, true)?;
    Ok(())
}

fn write_outcome(log: &mut BufWriter<File>, outcome: &SearchOutcome, console: bool) -> Result<()> {
    writeln!(log, "alpha: 0x{}", scalar_hex(&outcome.alpha))?;
    writeln!(log, "beta:  0x{}", scalar_hex(&outcome.beta))?;

    if let Some(delta) = outcome.delta {
        let d = derive_private_key(delta, outcome.alpha, outcome.beta);
        let hex = scalar_hex(&d);
        writeln!(log, "FOUND delta={delta} d=0x{hex}")?;
        emit_summary(
            Level::INFO,
            format!("event=search_result status=found delta={delta} d=0x{hex}"),
            console,
        );
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
fn resolve_path(base_dir: &Path, p: &str) -> Result<std::path::PathBuf> {
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
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_batch_normalize_identity() {
        use k256::elliptic_curve::BatchNormalize;
        let identity = ProjectivePoint::IDENTITY;
        let gen = ProjectivePoint::GENERATOR;
        let points = vec![identity, gen, identity];
        let _affines = ProjectivePoint::batch_normalize(points.as_slice());
    }

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
    fn test_search_negative_delta() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (pair, pk) = fixture();
        let out = temp_log("neg_delta_found");
        let spec = SearchSpec::new(-2, 0, 1).unwrap();
        let engine = SearchEngine::new(
            &ctx.config,
            None,
            ctx.shutdown.clone(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let outcome = engine.search(&spec, &pair, &pk).unwrap();
        assert_eq!(outcome.delta, Some(-1));

        let mut log = BufWriter::new(File::create(&out).unwrap());
        write_outcome(&mut log, &outcome, false).unwrap();
        let log = std::fs::read_to_string(&out).unwrap();
        assert!(log.contains("FOUND delta=-1"));
        assert!(log.contains(&format!("d=0x{}", scalar_hex(&Scalar::from(0x3039u64)))));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_search_no_match() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (pair, pk) = fixture();
        let out = temp_log("neg_delta_miss");
        let spec = SearchSpec::new(0, 0, 1).unwrap();
        let engine = SearchEngine::new(
            &ctx.config,
            None,
            ctx.shutdown.clone(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let outcome = engine.search(&spec, &pair, &pk).unwrap();
        assert_eq!(outcome.delta, None);

        let mut log = BufWriter::new(File::create(&out).unwrap());
        write_outcome(&mut log, &outcome, false).unwrap();
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
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (pair, pk) = fixture();
        let err = run_search(
            &ctx,
            &SearchArgs {
                r1: scalar_to_hex(&pair.first.r),
                r2: scalar_to_hex(&pair.second.r),
                s1: scalar_to_hex(&pair.first.s),
                s2: scalar_to_hex(&pair.second.s),
                z1: scalar_to_hex(&pair.first.z),
                z2: scalar_to_hex(&pair.second.z),
                pubkey: hex::encode(pk.to_encoded_point(true).as_bytes()),
                start: "-2".into(),
                end: "0".into(),
                step: "1".into(),
                threads: None,
                quiet: true,
                outfile: "   ".into(),
            },
        )
        .expect_err("should reject empty");
        assert!(err.to_string().contains("outfile"));
    }

    #[test]
    fn test_step_scalar_zero() {
        let config = Config {
            max_threads: 4,
            log_dir: std::env::temp_dir(),
            version: "test",
        };
        let ctx = AppContext::new(config);
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

        let pair = SignaturePair::new(Signature::new(r1, s1, z1), Signature::new(r2, s2, z2));
        let out = temp_log("step_zero");
        let spec = SearchSpec::new(0, 10, 1).unwrap();
        let engine = SearchEngine::new(
            &ctx.config,
            None,
            ctx.shutdown.clone(),
            Arc::new(TracingMetricsSink),
        )
        .unwrap();
        let outcome = engine.search(&spec, &pair, &pk).unwrap();
        assert_eq!(outcome.delta, Some(0));

        let mut log = BufWriter::new(File::create(&out).unwrap());
        write_outcome(&mut log, &outcome, false).unwrap();
        let log = std::fs::read_to_string(&out).unwrap();
        assert!(log.contains("FOUND delta=0"));
        let _ = std::fs::remove_file(&out);
    }

    fn fixture() -> (SignaturePair, PublicKey) {
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

        let sig1 = Signature::new(r1, s1, z1);
        let sig2 = Signature::new(r2, s2, z2);
        (SignaturePair::new(sig1, sig2), pk)
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
            version: "test",
        };
        let ctx = AppContext::new(config);
        let (pair, pk) = fixture();
        let err = run_search(
            &ctx,
            &SearchArgs {
                r1: scalar_to_hex(&pair.first.r),
                r2: scalar_to_hex(&pair.second.r),
                s1: scalar_to_hex(&pair.first.s),
                s2: scalar_to_hex(&pair.second.s),
                z1: scalar_to_hex(&pair.first.z),
                z2: scalar_to_hex(&pair.second.z),
                pubkey: hex::encode(pk.to_encoded_point(true).as_bytes()),
                start: "0".into(),
                end: "10".into(),
                step: "1".into(),
                threads: Some(0),
                quiet: true,
                outfile: "test.log".into(),
            },
        )
        .expect_err("should reject zero threads");
        assert!(err.to_string().contains("threads"));
    }
}
