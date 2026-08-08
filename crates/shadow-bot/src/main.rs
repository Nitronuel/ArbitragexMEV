use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::Arc,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, U256};
use catalog::{CycleLimits, parse_manifest};
use clap::{Parser, Subcommand};
use domain::ShadowConfig;
use enumerate::{CrawlPace, Venue, sweep_venue};
use provider::{
    ChainReader, LiveHttp, LiveHttpProbe, LiveRpc, LogStream, ProviderBudget, RedactedUrl,
    RetryPolicy, SubscriptionFilter, ThreadSleeper,
};
use shadow::{
    CostSnapshot, Economics, FIXED_POINT_SCALE, ServiceReport, ServiceSnapshot, daily_report,
    observe_snapshot, replay_observation, run_live, run_smoke,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use storage::Storage;

mod enumerate;
mod gaps;

const QUEUE_CAPACITY: usize = 100_000;
const CYCLE_LIMITS: CycleLimits = CycleLimits {
    max_cycles: 1_000_000,
    max_cycles_per_pool: 10_000,
};

/// An `AtomicBool` stop flag raised by SIGINT/SIGTERM for graceful drain.
struct StopOnSignal {
    flag: Arc<AtomicBool>,
    _ids: Vec<signal_hook::SigId>,
}

impl StopOnSignal {
    fn install() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let mut ids = Vec::new();
        for signal in [SIGTERM, SIGINT] {
            if let Ok(id) = signal_hook::flag::register(signal, Arc::clone(&flag)) {
                ids.push(id);
            }
        }
        Self { flag, _ids: ids }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "shadow-bot",
    version,
    about = "Read-only V2 shadow observer for Base"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validates the TOML configuration and RPC environment redaction.
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Parses and validates a candidate-pool manifest without RPC access.
    /// Just make simple builds of the manifest
    VerifyCatalog {
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        offline: bool,
    },
    /// Runs a bounded live-provider smoke test (chain, pinned catalog, Sync).
    SmokeTest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        block: Option<u64>,
        #[arg(long, default_value_t = 1000)]
        limit: u64,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
    },
    /// Runs the observation pipeline. Use `--manifest` for a bounded live run,
    /// otherwise an offline snapshot fixture.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        snapshot: Option<PathBuf>,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        block: Option<u64>,
        #[arg(long, default_value_t = 250)]
        poll_ms: u64,
        #[arg(long, default_value_t = 250)]
        drain_ms: u64,
        #[arg(long, default_value_t = 0)]
        max_items: u64,
        #[arg(long)]
        anchor: Vec<String>,
    },
    /// Reproduces one stored observation and fails on any mismatch.
    ReplayObservation {
        #[arg(value_name = "ID")]
        id: i64,
        #[arg(long)]
        db: PathBuf,
    },
    /// Renders a UTC daily report from the shadow database.
    DailyReport {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, value_name = "YYYY-MM-DD")]
        date: String,
    },
    /// Enumerates pools for a DEX venue across a block range (read-only).
    EnumeratePools {
        #[arg(long)]
        venue: String,
        #[arg(long)]
        factory: Address,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: Option<u64>,
        #[arg(long, default_value_t = 50_000)]
        window: u64,
        #[arg(long, default_value_t = 600)]
        delay_ms: u64,
        #[arg(value_name = "OUT")]
        out: PathBuf,
    },
    /// Counts cross-venue opportunities (shared pairs, optional 2/3-hop
    /// cycles) between two enumerated venue catalogs (read-only, offline).
    MeasureCrossVenues {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::ValidateConfig { config } => validate_config(&config),
        Command::VerifyCatalog {
            manifest,
            config,
            offline: _,
        } => verify_catalog_command(manifest, config),
        Command::SmokeTest {
            config,
            manifest,
            block,
            limit,
            timeout_secs,
        } => run_smoke_command(&config, &manifest, block, limit, timeout_secs),
        Command::Run {
            config,
            snapshot,
            db,
            manifest,
            block,
            poll_ms,
            drain_ms,
            max_items,
            anchor,
        } => run(
            &config,
            snapshot.as_deref(),
            &db,
            manifest.as_deref(),
            block,
            poll_ms,
            drain_ms,
            max_items,
            &anchor,
        ),
        Command::ReplayObservation { id, db } => replay_observation_command(id, &db),
        Command::DailyReport { db, date } => daily_report_command(&db, &date),
        Command::EnumeratePools {
            venue,
            factory,
            from,
            to,
            window,
            delay_ms,
            out,
        } => enumerate_pools_command(&venue, factory, from, to, window, delay_ms, &out),
        Command::MeasureCrossVenues { a, b } => measure_cross_venues_command(&a, &b),
    };
    if let Err(error) = outcome {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn validate_config(path: &std::path::Path) -> Result<(), String> {
    let config = ShadowConfig::load(path).map_err(|error| error.to_string())?;
    let chain = config
        .chain
        .map_or_else(|| "unknown".to_owned(), |chain| chain.name().to_owned());
    println!(
        "configuration valid: chain={} chain_id={} max_hops={} pool_cap={}",
        chain, config.chain_id, config.max_hops, config.pool_cap
    );
    Ok(())
}

fn verify_catalog(path: &std::path::Path) -> Result<(), String> {
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let candidates = parse_manifest(file).map_err(|error| error.to_string())?;
    println!("manifest valid: {} candidate pools", candidates.len());
    Ok(())
}

/// Resolves the manifest from `--manifest` or `--config`, then validates it
/// statically. The offline flag is a paranoia marker: no RPC calls are made.
fn verify_catalog_command(
    manifest: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<(), String> {
    let manifest_path = if let Some(path) = manifest {
        path
    } else {
        let config_path = config.ok_or_else(|| {
            "verify-catalog needs --manifest or --config (with manifest_path)".to_owned()
        })?;
        let parsed =
            ShadowConfig::manifest_path_from(&config_path).map_err(|error| error.to_string())?;
        parsed.ok_or_else(|| "--config has no manifest_path".to_owned())?
    };
    verify_catalog(&manifest_path)
}

fn enumerate_pools_command(
    venue_name: &str,
    factory: Address,
    from: u64,
    to: Option<u64>,
    window: u64,
    delay_ms: u64,
    out: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write;
    let venue = match venue_name {
        "v3" => Venue::v3_pools(factory),
        "v4" => Venue::v4_pools(factory),
        other => return Err(format!("unsupported venue {other:?}; use v3 or v4")),
    };
    let http = std::env::var("ROBINHOOD_HTTP_RPC_URL")
        .map_err(|_| "missing ROBINHOOD_HTTP_RPC_URL".to_owned())?;
    let http_url: RedactedUrl = http
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let budget = ProviderBudget::new(24_000_000, 10_000_000);
    let retry = RetryPolicy {
        max_retries: 3,
        initial_delay: Duration::from_millis(250),
        max_delay: Duration::from_secs(2),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url),
        ThreadSleeper,
        budget.clone(),
        retry,
        domain::ROBINHOOD_CHAIN_ID,
    );
    reader
        .validate_chain_id()
        .map_err(|error| error.to_string())?;
    let head = match to {
        Some(to) => to,
        None => reader.current_block().map_err(|error| error.to_string())?,
    };
    let pace = CrawlPace {
        window,
        delay: Duration::from_millis(delay_ms),
    };
    let pools =
        sweep_venue(&reader, &venue, from, head, pace).map_err(|error| error.to_string())?;
    let mut writer = std::fs::File::create(out).map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source"
    )
    .map_err(|error| error.to_string())?;
    for pool in &pools {
        let line = match pool {
            enumerate::EnumeratedPool::V3 {
                token0,
                token1,
                fee,
                pool: address,
            } => format!("4663,{address},{factory},{token0},{token1},{fee},1000000,v3,,\n"),
            enumerate::EnumeratedPool::V4 {
                id,
                currency0,
                currency1,
                fee,
                ..
            } => {
                format!("4663,{factory},{factory},{currency0},{currency1},{fee},1000000,v4,{id},\n")
            }
        };
        writer
            .write_all(line.as_bytes())
            .map_err(|error| error.to_string())?;
    }
    println!(
        "enumerated {} pools from venue {venue_name} blocks {from}..{head} -> {}",
        pools.len(),
        out.display()
    );
    Ok(())
}

fn measure_cross_venues_command(
    a_path: &std::path::Path,
    b_path: &std::path::Path,
) -> Result<(), String> {
    let catalog_a = gaps::load_catalog(a_path)?;
    let catalog_b = gaps::load_catalog(b_path)?;
    let report = gaps::cross_measure(&catalog_a, &catalog_b);
    println!(
        "cross-venue: catalog_a={} catalog_b={} cross_pairs={} toll_free={} three_hop={} tokens={}",
        catalog_a.len(),
        catalog_b.len(),
        report.cross_pairs,
        report.toll_free_cross_pairs,
        report.three_hop_cycles,
        report.cross_tokens,
    );
    Ok(())
}

fn run_smoke_command(
    config_path: &std::path::Path,
    manifest_path: &std::path::Path,
    block: Option<u64>,
    limit: u64,
    timeout_secs: u64,
) -> Result<(), String> {
    let config = ShadowConfig::load(config_path).map_err(|error| error.to_string())?;
    let chain = config
        .chain
        .ok_or_else(|| "configuration did not resolve a supported chain".to_owned())?;
    let http = std::env::var(chain.http_env_var())
        .map_err(|_| format!("missing {}", chain.http_env_var()))?;
    let http_url: RedactedUrl = http
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;

    let budget = ProviderBudget::new(config.request_cu_ceiling, config.websocket_bytes_ceiling);
    let retry = RetryPolicy {
        max_retries: 3,
        initial_delay: Duration::from_millis(250),
        max_delay: Duration::from_secs(2),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        config.chain_id,
    );
    let pinned = match block {
        Some(block) => block,
        None => reader.current_block().map_err(|error| error.to_string())?,
    };
    let rpc = LiveRpc::new(reader);
    let log_stream = LogStream::new(budget.clone());
    let probe_cadence = Duration::from_millis(200);
    let mut build_probe = |filter: SubscriptionFilter| {
        Ok(LiveHttpProbe::new(
            ChainReader::new(
                LiveHttp::new(http_url.clone()),
                ThreadSleeper,
                budget.clone(),
                retry,
                config.chain_id,
            ),
            filter.addresses,
            pinned,
            probe_cadence,
        ))
    };

    let limit_usize: usize =
        usize::try_from(limit).map_err(|_| "limit exceeds platform usize".to_owned())?;
    let report = run_smoke(
        fs::File::open(manifest_path).map_err(|error| error.to_string())?,
        pinned,
        limit_usize,
        Duration::from_secs(timeout_secs),
        &rpc,
        &log_stream,
        &mut build_probe,
    )
    .map_err(|error| error.to_string())?;

    let usage = budget.snapshot();
    println!(
        "smoke: block={} verified={} quarantined={} sync_received={} subscription_ok={}",
        report.block,
        report.verified,
        report.quarantined,
        report.sync_received,
        report.subscription_ok
    );
    println!(
        "usage: request_cu={} http_bytes={} ws_delivered={} ws_accounted={}",
        usage.request_cu,
        usage.http_response_bytes,
        usage.websocket_delivered_bytes,
        usage.websocket_accounted_bytes
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run(
    config_path: &std::path::Path,
    snapshot_path: Option<&std::path::Path>,
    db: &std::path::Path,
    manifest_path: Option<&std::path::Path>,
    block: Option<u64>,
    poll_ms: u64,
    drain_ms: u64,
    max_items: u64,
    anchors: &[String],
) -> Result<(), String> {
    let config = ShadowConfig::load(config_path).map_err(|error| error.to_string())?;
    let now_ms = unix_millis();
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: U256::from(1_000),
        expected_win_rate: U256::from(FIXED_POINT_SCALE),
    };
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
    };
    if let Some(manifest_path) = manifest_path {
        run_live_command(
            &config,
            manifest_path,
            db,
            block,
            poll_ms,
            drain_ms,
            max_items,
            anchors,
            economics,
            reference,
        )
    } else {
        let snapshot_path =
            snapshot_path.ok_or_else(|| "--snapshot is required without --manifest".to_owned())?;
        run_snapshot_command(snapshot_path, db, now_ms, economics, reference, &config)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_snapshot_command(
    snapshot_path: &std::path::Path,
    db: &std::path::Path,
    now_ms: u64,
    economics: Economics,
    reference: CostSnapshot,
    config: &ShadowConfig,
) -> Result<(), String> {
    let snapshot: ServiceSnapshot =
        serde_json::from_slice(&fs::read(snapshot_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let report = observe_snapshot(
        snapshot,
        now_ms,
        economics,
        reference,
        db,
        QUEUE_CAPACITY,
        CYCLE_LIMITS,
        config.request_cu_ceiling,
        config.websocket_bytes_ceiling,
    )
    .map_err(|error| error.to_string())?;
    print_report(&report);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_live_command(
    config: &ShadowConfig,
    manifest_path: &std::path::Path,
    db: &std::path::Path,
    block: Option<u64>,
    poll_ms: u64,
    drain_ms: u64,
    max_items: u64,
    anchors: &[String],
    economics: Economics,
    reference: CostSnapshot,
) -> Result<(), String> {
    let chain = config
        .chain
        .ok_or_else(|| "configuration did not resolve a supported chain".to_owned())?;
    let http = std::env::var(chain.http_env_var())
        .map_err(|_| format!("missing {}", chain.http_env_var()))?;
    let http_url: RedactedUrl = http
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;

    let budget = ProviderBudget::new(config.request_cu_ceiling, config.websocket_bytes_ceiling);
    let retry = RetryPolicy {
        max_retries: 3,
        initial_delay: Duration::from_millis(250),
        max_delay: Duration::from_secs(2),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        config.chain_id,
    );
    let pinned = if let Some(block) = block {
        block
    } else {
        reader.current_block().map_err(|error| error.to_string())?
    };
    let rpc = LiveRpc::new(reader);
    let log_stream = LogStream::new(budget.clone());

    let anchor_set: HashSet<Address> = anchors
        .iter()
        .map(|value| value.parse::<Address>().map_err(|error| error.to_string()))
        .collect::<Result<HashSet<_>, String>>()?;

    let max_items_usize: usize =
        usize::try_from(max_items).map_err(|_| "max-items exceeds platform usize".to_owned())?;
    let probe_cadence = Duration::from_millis(poll_ms);
    let mut build_probe = |addresses: &[Address]| {
        Ok(LiveHttpProbe::new(
            ChainReader::new(
                LiveHttp::new(http_url.clone()),
                ThreadSleeper,
                budget.clone(),
                retry,
                config.chain_id,
            ),
            addresses.to_vec(),
            pinned,
            probe_cadence,
        ))
    };
    let stop = StopOnSignal::install();
    let report = run_live(
        fs::File::open(manifest_path).map_err(|error| error.to_string())?,
        &anchor_set,
        pinned,
        &rpc,
        &log_stream,
        Duration::from_millis(poll_ms),
        Duration::from_millis(drain_ms),
        &stop.flag,
        max_items_usize,
        alloy_primitives::B256::ZERO,
        &mut build_probe,
        unix_millis(),
        economics,
        reference,
        db,
        QUEUE_CAPACITY,
        CYCLE_LIMITS,
        config.request_cu_ceiling,
        config.websocket_bytes_ceiling,
    )
    .map_err(|error| error.to_string())?;

    let usage = budget.snapshot();
    println!(
        "live: block={} pools={} cycles={} quarantined={} sync={} applied={} unknown={} evaluated={} recorded={} interesting={} ended={:?}",
        pinned,
        report.pool_count,
        report.cycle_count,
        report.quarantined,
        report.sync_observed,
        report.applied,
        report.unknown_pool,
        report.evaluated,
        report.recorded,
        report.interesting,
        report.ended,
    );
    println!(
        "usage: request_cu={} http_bytes={} ws_delivered={} ws_accounted={}",
        usage.request_cu,
        usage.http_response_bytes,
        usage.websocket_delivered_bytes,
        usage.websocket_accounted_bytes
    );
    Ok(())
}

fn print_report(report: &ServiceReport) {
    println!(
        "pools={} cycles={} quarantined={} evaluated={} recorded={} interesting={} not_evaluated={} requeued={} skipped_stale={} degraded={}",
        report.pool_count,
        report.cycle_count,
        report.quarantined,
        report.evaluated,
        report.recorded,
        report.interesting,
        report.not_evaluated,
        report.requeued,
        report.skipped_stale,
        report.degraded,
    );
}

fn replay_observation_command(id: i64, db: &std::path::Path) -> Result<(), String> {
    let storage = Storage::open(db).map_err(|error| error.to_string())?;
    let result = replay_observation(&storage, id).map_err(|error| error.to_string())?;
    println!(
        "observation {} cycle={} input={} output={} profit={} matched={}",
        result.observation_id,
        result.cycle_id.0,
        result.input,
        result.output,
        result.estimated_profit,
        result.matched,
    );
    if result.matched {
        Ok(())
    } else {
        Err(format!("observation {id} did not reproduce"))
    }
}

fn daily_report_command(db: &std::path::Path, date: &str) -> Result<(), String> {
    let (year, month, day) = parse_date(date)?;
    let storage = Storage::open(db).map_err(|error| error.to_string())?;
    let report = daily_report(&storage, year, month, day).map_err(|error| error.to_string())?;
    print!("{}", report.render());
    Ok(())
}

fn parse_date(date: &str) -> Result<(i32, u32, u32), String> {
    let mut parts = date.split('-');
    let year = parts
        .next()
        .ok_or_else(|| format!("invalid date {date}"))?
        .parse::<i32>()
        .map_err(|_| format!("invalid date {date}"))?;
    let month = parts
        .next()
        .ok_or_else(|| format!("invalid date {date}"))?
        .parse::<u32>()
        .map_err(|_| format!("invalid date {date}"))?;
    let day = parts
        .next()
        .ok_or_else(|| format!("invalid date {date}"))?
        .parse::<u32>()
        .map_err(|_| format!("invalid date {date}"))?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(format!("invalid date {date}"));
    }
    Ok((year, month, day))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
