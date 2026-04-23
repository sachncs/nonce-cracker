use clap::{Parser, Subcommand};
use hex::FromHex;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, BatchNormalize, PrimeField},
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
};
use rayon::prelude::*;
use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    num::ParseIntError,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info, warn, Level};

mod config;
mod logging;
mod metrics;

const NOT_FOUND: i64 = i64::MAX;
const BSGS_THRESHOLD: u128 = 1 << 32;
const BSGS_MAX_M: u64 = 1 << 26;
const IDENTITY_KEY: [u8; 33] = [0u8; 33];
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

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
impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
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
                    SHUTDOWN.store(true, Ordering::SeqCst);
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
        None => thread::available_parallelism()
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

#[allow(clippy::too_many_arguments)]
fn parallel_scan(
    target: PublicKey,
    start: i64,
    step: i64,
    total: u128,
    thread_count: usize,
    alpha: Scalar,
    beta: Scalar,
    step_point: ProjectivePoint,
) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *target.as_affine();
    let chunk: u128 = total.div_ceil(thread_count as u128);
    let result = Arc::new(AtomicI64::new(NOT_FOUND));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    const BATCH: u128 = 1024;

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|thread_id| {
            if shutdown() {
                return;
            }
            let chunk_start = thread_id as u128 * chunk;
            if chunk_start >= total {
                return;
            }
            let count = chunk.min(total - chunk_start);

            let start_delta = start as i128 + chunk_start as i128 * step as i128;
            let mut d0 = match i64::try_from(start_delta) {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut point = ProjectivePoint::GENERATOR * derive_private_key(d0, alpha, beta);

            let mut i = 0u128;
            while i < count {
                if shutdown() || result.load(Ordering::Acquire) != NOT_FOUND {
                    break;
                }
                let batch_end = (i + BATCH).min(count);
                let mut found = false;
                for _ in i..batch_end {
                    if point == target_affine {
                        let _ = result.compare_exchange(
                            NOT_FOUND,
                            d0,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        );
                        found = true;
                        break;
                    }
                    point += step_point;
                    d0 = d0.wrapping_add(step);
                }
                i = batch_end;
                if found {
                    break;
                }
            }
        });
    });

    let found = result.load(Ordering::SeqCst);
    if found != NOT_FOUND {
        Ok(Some(found))
    } else {
        Ok(None)
    }
}

#[allow(clippy::too_many_arguments)]
fn bsgs(
    target: PublicKey,
    start: i64,
    step: i64,
    total: u128,
    thread_count: usize,
    alpha: Scalar,
    beta: Scalar,
    step_point: ProjectivePoint,
) -> Result<Option<i64>> {
    let target_affine: AffinePoint = *target.as_affine();
    let d0_scalar = derive_private_key(start, alpha, beta);
    let d0_point = ProjectivePoint::GENERATOR * d0_scalar;

    if d0_point == target_affine {
        return Ok(Some(start));
    }

    let mut t: ProjectivePoint = target_affine.into();
    t -= d0_point;

    let total_u64 = total as u64;
    let mut m = (total_u64 as f64).sqrt().ceil() as u64;
    if m == 0 {
        m = 1;
    }
    while (m as u128) * (m as u128) < total {
        m += 1;
    }
    while m > 1 && ((m - 1) as u128) * ((m - 1) as u128) >= total {
        m -= 1;
    }

    if m > BSGS_MAX_M {
        return Err(Error(format!(
            "BSGS memory limit exceeded (m={m} > {BSGS_MAX_M}). Range too large for BSGS."
        )));
    }

    let m_scalar = Scalar::from(m);
    let m_step = step_point * m_scalar;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .map_err(|e| Error(format!("thread pool: {e}")))?;

    let baby_map = pool.install(|| build_baby_steps(m, step_point, thread_count));

    let result = Arc::new(AtomicU64::new(u64::MAX));

    const BATCH: u64 = 4096;

    pool.install(|| {
        (0..thread_count).into_par_iter().for_each(|tid| {
            if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                return;
            }
            let chunk_start = tid as u128 * m as u128 / thread_count as u128;
            let chunk_end = ((tid + 1) as u128 * m as u128 / thread_count as u128).min(m as u128);
            if chunk_start >= chunk_end {
                return;
            }

            let chunk_start_u64 = chunk_start as u64;
            let chunk_end_u64 = chunk_end as u64;
            let coeff = chunk_start_u64 * m;
            let offset = step_point * Scalar::from(coeff);
            let mut giant = t - offset;

            let mut i = chunk_start_u64;
            while i < chunk_end_u64 {
                if shutdown() || result.load(Ordering::Acquire) != u64::MAX {
                    break;
                }
                let batch_end = (i + BATCH).min(chunk_end_u64);
                let mut entries: Vec<(u64, ProjectivePoint)> =
                    Vec::with_capacity((batch_end - i) as usize);
                let mut current = giant;
                for idx in 0..(batch_end - i) {
                    if current == ProjectivePoint::IDENTITY {
                        if let Some(&j) = baby_map.get(&IDENTITY_KEY) {
                            let k = (i + idx) * m + j;
                            if k < total_u64 {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    k,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                return;
                            }
                        }
                        current -= m_step;
                        continue;
                    }
                    entries.push((idx, current));
                    current -= m_step;
                }

                if !entries.is_empty() {
                    let points: Vec<ProjectivePoint> = entries.iter().map(|(_, p)| *p).collect();
                    let affines: Vec<AffinePoint> =
                        ProjectivePoint::batch_normalize(points.as_slice());
                    for (affine_idx, affine) in affines.iter().enumerate() {
                        let idx = entries[affine_idx].0;
                        let key = affine_key(affine);
                        if let Some(&j) = baby_map.get(&key) {
                            let k = (i + idx) * m + j;
                            if k < total_u64 {
                                let _ = result.compare_exchange(
                                    u64::MAX,
                                    k,
                                    Ordering::SeqCst,
                                    Ordering::Relaxed,
                                );
                                return;
                            }
                        }
                    }
                }

                giant = current;
                i = batch_end;
            }
        });
    });

    let found_k = result.load(Ordering::SeqCst);
    if found_k != u64::MAX {
        let delta_i128 = start as i128 + (found_k as i128) * (step as i128);
        let delta = i64::try_from(delta_i128).map_err(|_| Error("delta overflow".into()))?;
        Ok(Some(delta))
    } else {
        Ok(None)
    }
}

fn build_baby_steps(
    m: u64,
    step_point: ProjectivePoint,
    thread_count: usize,
) -> HashMap<[u8; 33], u64> {
    let maps: Vec<HashMap<[u8; 33], u64>> = (0..thread_count)
        .into_par_iter()
        .map(|tid| {
            let start_j = tid as u64 * m / thread_count as u64;
            let end_j = ((tid + 1) as u64 * m / thread_count as u64).min(m);
            if start_j >= end_j {
                return HashMap::new();
            }
            let mut map = HashMap::with_capacity((end_j - start_j) as usize);

            if start_j == 0 {
                map.insert(IDENTITY_KEY, 0);
            }

            const BATCH: u64 = 4096;
            let mut j = if start_j == 0 { 1 } else { start_j };
            let mut current = step_point * Scalar::from(j);

            while j < end_j {
                let batch_end = (j + BATCH).min(end_j);
                let batch_size = (batch_end - j) as usize;
                let mut points = Vec::with_capacity(batch_size);

                for _ in 0..batch_size {
                    points.push(current);
                    current += step_point;
                }

                let affines: Vec<AffinePoint> = ProjectivePoint::batch_normalize(points.as_slice());

                for (idx, affine) in affines.iter().enumerate() {
                    let key = affine_key(affine);
                    map.insert(key, j + idx as u64);
                }

                j = batch_end;
            }
            map
        })
        .collect();

    let mut merged = HashMap::with_capacity(m as usize);
    for map in maps {
        merged.extend(map);
    }
    merged
}

#[inline]
fn affine_key(affine: &AffinePoint) -> [u8; 33] {
    let enc = affine.to_encoded_point(true);
    let bytes = enc.as_bytes();
    let mut key = [0u8; 33];
    key[..bytes.len()].copy_from_slice(bytes);
    key
}

#[inline(always)]
fn derive_private_key(delta: i64, alpha: Scalar, beta: Scalar) -> Scalar {
    let s = Scalar::from(delta.unsigned_abs());
    if delta < 0 {
        beta - alpha * s
    } else {
        alpha * s + beta
    }
}

fn derive_affine_constants(
    r1: Scalar,
    r2: Scalar,
    s1: Scalar,
    s2: Scalar,
    z1: Scalar,
    z2: Scalar,
) -> Result<(Scalar, Scalar)> {
    let u: Scalar = Option::from(s1.invert()).ok_or_else(|| Error("s1 not invertible".into()))?;
    let a: Scalar = s2 * r1 * u - r2;
    let b: Scalar = z2 - s2 * z1 * u;
    let c: Scalar = s2;
    let a_inv: Scalar =
        Option::from(a.invert()).ok_or_else(|| Error("denominator not invertible".into()))?;
    Ok((-(c * a_inv), b * a_inv))
}

fn parse_scalar(s: &str) -> Result<Scalar> {
    let raw = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Err(Error("empty hex string".into()));
    }
    let padded = if raw.len() % 2 == 1 {
        format!("0{raw}")
    } else {
        raw.to_string()
    };
    let bytes = Vec::from_hex(&padded)?;
    if bytes.len() > 32 {
        return Err(Error("scalar exceeds 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    Option::from(Scalar::from_repr(arr.into())).ok_or_else(|| Error("scalar out of range".into()))
}

fn parse_pubkey(s: &str) -> Result<PublicKey> {
    let bytes = Vec::from_hex(s.trim().trim_start_matches("0x").trim_start_matches("0X"))?;
    match bytes.first() {
        Some(0x02) | Some(0x03) if bytes.len() == 33 => {
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error(format!("pubkey: {e}")))
        }
        Some(0x04) if bytes.len() == 65 => {
            PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error(format!("pubkey: {e}")))
        }
        _ => Err(Error("pubkey: use 02, 03, or 04 prefix".into())),
    }
}

fn parse_int(s: &str) -> Result<i64> {
    let s = s.trim();
    let (neg, body) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };

    let mag = if body.starts_with("0x") || body.starts_with("0X") {
        u128::from_str_radix(&body[2..], 16).map_err(|e| Error(format!("parse error: {e}")))?
    } else {
        body.parse::<u128>()
            .map_err(|e| Error(format!("parse error: {e}")))?
    };

    if neg {
        if mag > (i64::MAX as u128) + 1 {
            return Err(Error("value overflows i64".into()));
        }
        i64::try_from(-(mag as i128)).map_err(|_| Error("value overflows i64".into()))
    } else {
        i64::try_from(mag).map_err(|_| Error("value overflows i64".into()))
    }
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

fn scalar_hex(s: &Scalar) -> String {
    let bytes = s.to_bytes();
    match bytes.iter().position(|b| *b != 0) {
        None => "0".into(),
        Some(i) => hex::encode(&bytes[i..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_precompute_and_private_key() {
        let (a, b) = derive_affine_constants(
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
            Scalar::from(5u64),
            Scalar::from(6u64),
        )
        .unwrap();
        assert_eq!(derive_private_key(0, a, b), b);
    }

    #[test]
    fn test_pubkey_conversion() {
        let pk_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk = parse_pubkey(pk_hex).unwrap();
        assert_eq!(hex::encode(pk.to_encoded_point(true).as_bytes()), pk_hex);
    }

    #[test]
    fn test_hex_parsing() {
        assert_eq!(parse_scalar("0xFF").unwrap(), parse_scalar("FF").unwrap());
        assert_eq!(
            parse_scalar("0xFFF").unwrap(),
            parse_scalar("0x0FFF").unwrap()
        );
    }

    #[test]
    fn test_range_parsing() {
        assert_eq!(parse_int("0").unwrap(), 0);
        assert_eq!(parse_int("100").unwrap(), 100);
        assert_eq!(parse_int("0xFF").unwrap(), 255);
        assert_eq!(parse_int("-0xFF").unwrap(), -255);
    }

    #[test]
    fn test_signed_delta() {
        let a = Scalar::from(1u64);
        let b = Scalar::from(2u64);
        assert_eq!(derive_private_key(-1, a, b), b - a);
    }

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
    fn test_pubkey_invalid() {
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("0xgg").is_err());
        assert!(parse_pubkey("01").is_err());
        assert!(parse_pubkey(&("02".to_string() + &"ff".repeat(31))).is_err());
        assert!(
            parse_pubkey("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .is_ok()
        );
        let uncompressed = concat!(
            "04",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert!(parse_pubkey(uncompressed).is_ok());
    }

    #[test]
    fn test_edge_cases() {
        assert!(derive_affine_constants(
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(1u64),
            Scalar::from(1u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
        )
        .is_ok());
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
