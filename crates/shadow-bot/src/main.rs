use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::Arc,
    sync::atomic::AtomicBool,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, U256};
use catalog::{CycleLimits, parse_manifest};
use clap::{Parser, Subcommand};
use domain::ShadowConfig;
use enumerate::{CrawlPace, Venue, sweep_venue};
use provider::{
    ChainReader, LiveHttp, LiveHttpProbe, LiveRpc, LiveWsClient, LogStream, ProviderBudget,
    RedactedUrl, RetryPolicy, StreamItem, SubscriptionFilter, ThreadSleeper, TransportError,
    WsProbe,
};
use shadow::{
    CostSnapshot, Economics, FIXED_POINT_SCALE, ServiceReport, ServiceSnapshot, daily_report,
    observe_snapshot, replay_observation, run_live, run_smoke,
};
use signal_hook::consts::{SIGINT, SIGTERM};
use storage::Storage;

mod dirty;
mod enumerate;
mod gaps;
mod ws_probe;

const QUEUE_CAPACITY: usize = 100_000;
const CYCLE_LIMITS: CycleLimits = CycleLimits {
    max_cycles: 1_000_000,
    max_cycles_per_pool: 10_000,
};

/// Conservative gas cost of one cross-venue attempt in USD fixed-point
/// (~$0.03, per the project budget rules). At 18 fp digits this is 3e16.
const GAS_COST_USD: U256 = U256::from_limbs([30_000_000_000_000_000, 0, 0, 0]);
/// Expected win rate used for the submission-gate floor (10%).
const EXPECTED_WIN_RATE: U256 = U256::from_limbs([100_000_000_000_000_000, 0, 0, 0]);

/// Uniswap V4 `PoolManager` singleton on Base; emits all Swap logs with the
/// pool id as topic1 (confirmed from the enumerated catalog).
const V4_POOL_MANAGER: Address =
    alloy_primitives::address!("0x8366a39CC670B4001A1121B8F6A443A643e40951");

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
    /// Probes a live WebSocket endpoint with per-venue filtered Swap-log
    /// subscriptions and reports tip-lag and byte usage. Read-only.
    WsProbe {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value_t = 300)]
        duration_secs: u64,
        #[arg(long, default_value_t = 0)]
        limit: u64,
        #[arg(long, default_value_t = 5000)]
        tip_interval_ms: u64,
        #[arg(long, default_value_t = 8_000_000)]
        request_cu: u64,
        #[arg(long, default_value_t = 268_435_456)]
        ws_bytes: u64,
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
    /// Samples live Swap prices (latest per pool) across two venue catalogs
    /// over a block window and reports the gap-vs-toll distribution (read-only).
    GapVsToll {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
        /// Venue label for catalog A, one of `v3` or `v4`.
        #[arg(long, default_value = "v3")]
        profile_a: String,
        /// Venue label for catalog B, one of `v3` or `v4`.
        #[arg(long, default_value = "v4")]
        profile_b: String,
        /// v4 `PoolManager` contract address (only required when a profile is v4).
        #[arg(long)]
        pool_manager: Option<Address>,
        /// Base chain endpoint URL.
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long, default_value_t = 50_000)]
        window: u64,
        #[arg(long, default_value_t = 600)]
        delay_ms: u64,
        /// Print the top N cross-venue pairs ranked by (skew - toll) margin.
        #[arg(long, default_value_t = 0)]
        top: usize,
        /// Drop pairs whose skew is below this margin floor.
        #[arg(long, default_value_t = 0.0)]
        min_margin: f64,
        /// Drop pairs whose |log2 skew| exceeds this cap (catches degenerate
        /// near-empty pool price gaps that are not captureable).
        #[arg(long, default_value = "0.5")]
        max_skew: f64,
        /// Write each selected pair as one CSV row to this path (overwrites).
        #[arg(long)]
        csv: Option<PathBuf>,
    },
    /// Expands a selected-pairs CSV into a concrete-pool manifest, merging the
    /// pools from two enumerated catalogs that carry the selected pairs
    /// (read-only, offline).
    BuildManifest {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
        /// `gap-vs-toll --csv` selection output (`token_lo,token_hi,...`).
        #[arg(long)]
        selection: PathBuf,
        /// Hard cap on manifest pool rows (mirrors the catalog manifest cap).
        #[arg(long, default_value_t = 2_000)]
        pool_cap: usize,
        #[arg(value_name = "OUT")]
        out: PathBuf,
    },
    /// Samples live Swap prices over the enumerated manifest and emits the
    /// closed-form optimal round-trip quote per cross-venue pair (read-only).
    QuoteManifest {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
        /// Restrict the live sweep to the pools of this manifest CSV (the
        /// selected-seed list), instead of the full catalogs in `--a`/`--b`.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Venue label for catalog A, one of `v3` or `v4`.
        #[arg(long, default_value = "v3")]
        profile_a: String,
        /// Venue label for catalog B, one of `v3` or `v4`.
        #[arg(long, default_value = "v4")]
        profile_b: String,
        /// v4 `PoolManager` contract address (only required when a profile is v4).
        #[arg(long)]
        pool_manager: Option<Address>,
        /// Base chain endpoint URL.
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long, default_value_t = 50_000)]
        window: u64,
        #[arg(long, default_value_t = 600)]
        delay_ms: u64,
        /// Write one quote row per captureable pair to this path (overwrites).
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Token-price CSV (`token,usd_per_token`, fixed-point) for honest
        /// USD gating instead of the `$1` fixture.
        #[arg(long)]
        prices: Option<PathBuf>,
        /// Maximum `|log2 skew|` a quote may carry and still be gated.
        /// Larger gaps come from degenerate near-empty pools that are not
        /// captureable; they are screened out instead of surfacing as
        /// `AboveThreshold` at meaningless USD values.
        #[arg(long, default_value_t = 0.5)]
        max_skew: f64,
    },
    /// Sweeps the USDG/WETH-anchored legs for the manifest's seed tokens and
    /// derives a `token,usd_per_token` fixed-point price CSV from the median
    /// reserve ratios (read-only). WETH is priced first via its USDG legs;
    /// tokens without a priced USDG leg in the window fall back through their
    /// native WETH legs.
    DerivePrices {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
        /// Manifest CSV whose seed tokens define the USD legs to sweep
        /// (the selected-seed list).
        #[arg(long)]
        manifest: PathBuf,
        /// Venue label for catalog A, one of `v3` or `v4`.
        #[arg(long, default_value = "v3")]
        profile_a: String,
        /// Venue label for catalog B, one of `v3` or `v4`.
        #[arg(long, default_value = "v4")]
        profile_b: String,
        /// v4 `PoolManager` contract address (only required when a profile is v4).
        #[arg(long)]
        pool_manager: Option<Address>,
        /// Base chain endpoint URL.
        #[arg(long)]
        rpc: String,
        #[arg(long)]
        from: u64,
        #[arg(long)]
        to: u64,
        #[arg(long, default_value_t = 50_000)]
        window: u64,
        #[arg(long, default_value_t = 600)]
        delay_ms: u64,
        /// Write the derived prices to this `token,usd_per_token` CSV
        /// (overwrites).
        #[arg(value_name = "OUT")]
        out: PathBuf,
    },
    /// Polls live Swap prices from the chain tip and re-checks only the
    /// cross-venue pairs touched by each changed pool, gating each re-quote
    /// through the conservative economics floor (read-only).
    RunPairs {
        /// Enumerated catalog A (e.g. v3) CSV written by `enumerate-pools`.
        #[arg(long)]
        a: PathBuf,
        /// Enumerated catalog B (e.g. v4) CSV written by `enumerate-pools`.
        #[arg(long)]
        b: PathBuf,
        /// Restrict the live sweep to the pools of this manifest CSV (the
        /// selected-seed list), instead of the full catalogs in `--a`/`--b`.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Venue label for catalog A, one of `v3` or `v4`.
        #[arg(long, default_value = "v3")]
        profile_a: String,
        /// Venue label for catalog B, one of `v3` or `v4`.
        #[arg(long, default_value = "v4")]
        profile_b: String,
        /// v4 `PoolManager` contract address (only required when a profile is v4).
        #[arg(long)]
        pool_manager: Option<Address>,
        /// Base chain endpoint URL.
        #[arg(long)]
        rpc: String,
        /// Block to poll from (inclusive); defaults to the current tip.
        #[arg(long)]
        from: Option<u64>,
        /// Poll cadence in milliseconds.
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
        /// Drained swap events after which the loop stops (0 = unbounded).
        #[arg(long, default_value_t = 0)]
        max_swaps: u64,
        /// Wall-clock seconds after which the loop stops (0 = unbounded). The
        /// 24h canary uses this as its self-terminating bound.
        #[arg(long, default_value_t = 0)]
        duration_secs: u64,
        /// Width of each `eth_getLogs` window in blocks.
        #[arg(long, default_value_t = 50_000)]
        window: u64,
        /// Minimum poll delay between `eth_getLogs` requests.
        #[arg(long, default_value_t = 600)]
        delay_ms: u64,
        /// Write one row per gated pair per poll to this path (appends;
        /// headers written on first open). Columns: `token_lo,token_hi`,
        /// `to_block,input,output,profit,log2_skew,gross_profit_usd`,
        /// `net_profit_usd,threshold_usd`.
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Token-price CSV (`token,usd_per_token`, fixed-point) for honest
        /// USD gating instead of the `$1` fixture.
        #[arg(long)]
        prices: Option<PathBuf>,
        /// V3 catalog address-chunks swept per poll in the ring sweep. When
        /// zero, the default covers the whole V3 universe within ~1h at the
        /// configured `--poll-ms`.
        #[arg(long, default_value_t = 0)]
        v3_chunks_per_poll: u64,
        /// Maximum `|log2 skew|` a quote may carry and still be gated.
        /// Larger gaps come from degenerate near-empty pools that are not
        /// captureable; they are screened out instead of surfacing as
        /// `AboveThreshold` at meaningless USD values.
        #[arg(long, default_value_t = 0.5)]
        max_skew: f64,
        /// Maximum age in blocks (vs the poll tip) a quote's oldest leg price
        /// may carry and still be gated. A refresh-starved reference leg —
        /// priced once and never re-priced by the V3 ring sweep — produces a
        /// pseudo-gap against the fresh V4 side; quotes older than this bound
        /// are screened out instead of surfacing as `AboveThreshold`. `0`
        /// disables the screen.
        #[arg(long, default_value_t = 0)]
        max_price_age: u64,
    },
}

#[allow(clippy::too_many_lines)]
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
        Command::WsProbe {
            manifest,
            duration_secs,
            limit,
            tip_interval_ms,
            request_cu,
            ws_bytes,
        } => run_ws_probe_command(
            &manifest,
            duration_secs,
            limit,
            tip_interval_ms,
            request_cu,
            ws_bytes,
        ),
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
        Command::GapVsToll {
            a,
            b,
            profile_a,
            profile_b,
            pool_manager,
            rpc,
            from,
            to,
            window,
            delay_ms,
            top,
            min_margin,
            max_skew,
            csv,
        } => gap_vs_toll_command(&GapVsTollArgs {
            a: &a,
            b: &b,
            profile_a: &profile_a,
            profile_b: &profile_b,
            pool_manager,
            rpc: &rpc,
            from,
            to,
            window,
            delay_ms,
            top,
            min_margin,
            max_skew,
            csv: csv.as_deref(),
        }),
        Command::BuildManifest {
            a,
            b,
            selection,
            pool_cap,
            out,
        } => build_manifest_command(&a, &b, &selection, pool_cap, &out),
        Command::QuoteManifest {
            a,
            b,
            manifest,
            profile_a,
            profile_b,
            pool_manager,
            rpc,
            from,
            to,
            window,
            delay_ms,
            csv,
            prices,
            max_skew,
        } => quote_manifest_command(&QuoteManifestArgs {
            a: &a,
            b: &b,
            manifest: manifest.as_deref(),
            profile_a: &profile_a,
            profile_b: &profile_b,
            pool_manager,
            rpc: &rpc,
            from,
            to,
            window,
            delay_ms,
            csv: csv.as_deref(),
            prices: prices.as_deref(),
            max_skew,
        }),
        Command::DerivePrices {
            a,
            b,
            manifest,
            profile_a,
            profile_b,
            pool_manager,
            rpc,
            from,
            to,
            window,
            delay_ms,
            out,
        } => derive_prices_command(&DerivePricesArgs {
            a: &a,
            b: &b,
            manifest: &manifest,
            profile_a: &profile_a,
            profile_b: &profile_b,
            pool_manager,
            rpc: &rpc,
            from,
            to,
            window,
            delay_ms,
            out: &out,
        }),
        Command::RunPairs {
            a,
            b,
            manifest,
            profile_a,
            profile_b,
            pool_manager,
            rpc,
            from,
            poll_ms,
            max_swaps,
            duration_secs,
            window,
            delay_ms,
            csv,
            prices,
            v3_chunks_per_poll,
            max_skew,
            max_price_age,
        } => run_pairs_command(&RunPairsArgs {
            a: &a,
            b: &b,
            manifest: manifest.as_deref(),
            profile_a: &profile_a,
            profile_b: &profile_b,
            pool_manager,
            rpc: &rpc,
            from,
            poll_ms,
            max_swaps,
            duration_secs,
            window,
            delay_ms,
            csv: csv.as_deref(),
            prices: prices.as_deref(),
            v3_chunks_per_poll,
            max_skew,
            max_price_age,
        }),
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

/// Expands a `gap-vs-toll --csv` pair selection into a concrete-pool manifest
/// by keeping, from both enumerated catalogs, every pool whose normalized pair
/// is in the selection. Manifest rows keep each pool's catalog lineage so
/// `enumerate-pools` readers can re-load them. Read-only; requires no RPC.
fn build_manifest_command(
    a_path: &std::path::Path,
    b_path: &std::path::Path,
    selection_path: &std::path::Path,
    pool_cap: usize,
    out: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write;

    let catalog_a = gaps::load_catalog(a_path)?;
    let catalog_b = gaps::load_catalog(b_path)?;
    let catalog_a: Vec<_> = catalog_a.into_values().collect();
    let catalog_b: Vec<_> = catalog_b.into_values().collect();
    let selected = gaps::load_selected_pairs(selection_path)?;
    if selected.is_empty() {
        return Err("selection contains no pairs".to_owned());
    }
    let mut entries = gaps::expand_manifest_catalog(&catalog_a, &catalog_b, &selected, pool_cap)?;
    entries.sort_by_key(|entry| {
        (
            entry.chain_id,
            entry.factory,
            entry.profile,
            entry.venue,
            entry.id,
        )
    });
    let mut writer =
        std::io::BufWriter::new(std::fs::File::create(out).map_err(|error| error.to_string())?);
    writeln!(
        writer,
        "chain_id,pool_address,factory_address,token0,token1,fee_numerator,fee_denominator,profile,pool_id,source"
    )
    .map_err(|error| error.to_string())?;
    for entry in &entries {
        let pool_id = if entry.profile == *b"v4" {
            let mut hex = String::with_capacity(66);
            hex.push_str("0x");
            for byte in entry.id {
                use std::fmt::Write as _;
                write!(hex, "{byte:02x}").map_err(|error| error.to_string())?;
            }
            hex
        } else {
            String::new()
        };
        let profile = std::str::from_utf8(&entry.profile)
            .map_err(|_| "catalog profile is not utf8".to_owned())?;
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{profile},{pool_id},selection",
            entry.chain_id,
            entry.venue,
            entry.factory,
            entry.token0,
            entry.token1,
            entry.fee,
            entry.fee_denominator,
        )
        .map_err(|error| error.to_string())?;
    }
    println!(
        "manifest: {} pool rows from {} selected pairs -> {}",
        entries.len(),
        selected.len(),
        out.display()
    );
    Ok(())
}

/// Arguments for [`gap_vs_toll_command`].
struct GapVsTollArgs<'a> {
    a: &'a PathBuf,
    b: &'a PathBuf,
    profile_a: &'a str,
    profile_b: &'a str,
    pool_manager: Option<Address>,
    rpc: &'a str,
    from: u64,
    to: u64,
    window: u64,
    delay_ms: u64,
    top: usize,
    min_margin: f64,
    max_skew: f64,
    csv: Option<&'a std::path::Path>,
}

/// Arguments for [`quote_manifest_command`].
struct QuoteManifestArgs<'a> {
    a: &'a PathBuf,
    b: &'a PathBuf,
    manifest: Option<&'a std::path::Path>,
    profile_a: &'a str,
    profile_b: &'a str,
    pool_manager: Option<Address>,
    rpc: &'a str,
    from: u64,
    to: u64,
    window: u64,
    delay_ms: u64,
    csv: Option<&'a std::path::Path>,
    prices: Option<&'a std::path::Path>,
    /// Maximum `|log2 skew|` a quote may carry and still be gated; quotes
    /// above it are screened out as uncaptureable.
    max_skew: f64,
}

/// Arguments for [`derive_prices_command`].
struct DerivePricesArgs<'a> {
    a: &'a PathBuf,
    b: &'a PathBuf,
    manifest: &'a std::path::Path,
    profile_a: &'a str,
    profile_b: &'a str,
    pool_manager: Option<Address>,
    rpc: &'a str,
    from: u64,
    to: u64,
    window: u64,
    delay_ms: u64,
    out: &'a PathBuf,
}

/// Samples live Swap prices across two catalogs and reports the skew-vs-toll
/// distribution. Read-only; no signing or submission.
#[allow(clippy::too_many_lines)]
fn gap_vs_toll_command(args: &GapVsTollArgs<'_>) -> Result<(), String> {
    let a_path: &std::path::Path = args.a;
    let b_path: &std::path::Path = args.b;
    let rpc = args.rpc;
    let from = args.from;
    let to = args.to;
    let window = args.window;
    let delay_ms = args.delay_ms;
    let top = args.top;
    let min_margin = args.min_margin;
    let max_skew = args.max_skew;
    let csv_path = args.csv;
    let pool_manager = args.pool_manager;
    let profile_a = args.profile_a;
    let profile_b = args.profile_b;
    let catalog_a = gaps::load_catalog(a_path)?;
    let catalog_b = gaps::load_catalog(b_path)?;
    let (profile_bytes_a, profile_bytes_b) = (
        profile_a
            .as_bytes()
            .try_into()
            .map_err(|_| format!("profile_a must be exactly 2 bytes, got {profile_a}"))?,
        profile_b.as_bytes().try_into().unwrap(),
    );
    for (label, profile) in [(profile_a, &profile_bytes_a), (profile_b, &profile_bytes_b)] {
        if profile != b"v3" && profile != b"v4" {
            return Err(format!("unsupported venue {label:?}: expected v3 or v4"));
        }
    }
    let http_url: RedactedUrl = rpc
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let budget = ProviderBudget::new(40_000, 1 << 24);
    let retry = RetryPolicy {
        max_retries: 8,
        initial_delay: Duration::from_millis(600),
        max_delay: Duration::from_secs(12),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        8453,
    );
    let (cross_a, cross_b) = gaps::restrict_to_cross(&catalog_a, &catalog_b);
    println!("cross pools: a={} b={}", cross_a.len(), cross_b.len());
    let prices_a = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_a,
        pool_manager.unwrap_or(V4_POOL_MANAGER),
        &cross_a,
        from,
        to,
        window,
        Duration::from_millis(delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;
    let prices_b = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_b,
        pool_manager.unwrap_or(V4_POOL_MANAGER),
        &cross_b,
        from,
        to,
        window,
        Duration::from_millis(delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;
    let s = gaps::gap_distribution(&cross_a, &cross_b, &prices_a, &prices_b);
    println!(
        "gap-vs-toll: observed={} above_toll={} above_1pct={} pct_skewed={:.3} median_skew={:.6} median_toll={:.6} samples_a={} samples_b={}",
        s.observed_pairs,
        s.above_toll,
        s.above_1pct,
        s.pct_skewed,
        s.median_log2_skew,
        s.median_toll,
        prices_a.len(),
        prices_b.len(),
    );
    if top > 0 || csv_path.is_some() {
        use std::io::Write;
        let ranks = gaps::gap_rankings(&cross_a, &cross_b, &prices_a, &prices_b);
        let selected: Vec<_> = ranks
            .iter()
            .filter(|r| r.margin >= min_margin && r.log2_skew <= max_skew)
            .collect();
        if let Some(path) = csv_path {
            let mut out =
                std::io::BufWriter::new(std::fs::File::create(path).map_err(|e| e.to_string())?);
            writeln!(out, "token_lo,token_hi,log2_skew,toll,margin").map_err(|e| e.to_string())?;
            for rank in &selected {
                writeln!(
                    out,
                    "{},{},{:.6},{:.6},{:.6}",
                    rank.token_lo, rank.token_hi, rank.log2_skew, rank.toll, rank.margin
                )
                .map_err(|e| e.to_string())?;
            }
            println!(
                "wrote {} selected pairs -> {}",
                selected.len(),
                path.display()
            );
        }
        if top > 0 {
            println!("top-{top} selected pairs by skew-vs-toll margin:");
            for rank in selected.iter().take(top) {
                println!(
                    "{}::{}\tmargin={:.6}\tskew={:.6}\ttoll={:.6}",
                    rank.token_lo, rank.token_hi, rank.margin, rank.log2_skew, rank.toll,
                );
            }
        }
    }
    Ok(())
}

/// Samples live prices over the enumerated pair overlap and emits the closed
/// form optimal round trip per captureable pair (positive-profit cycles only).
#[allow(clippy::too_many_lines)]
fn quote_manifest_command(args: &QuoteManifestArgs<'_>) -> Result<(), String> {
    use std::io::Write;

    let a_path: &std::path::Path = args.a;
    let b_path: &std::path::Path = args.b;
    let manifest_path = args.manifest;
    let profile_a = args.profile_a;
    let profile_b = args.profile_b;
    let pool_manager = args.pool_manager;
    let from = args.from;
    let to = args.to;
    let window = args.window;
    let delay_ms = args.delay_ms;
    let csv_path = args.csv;
    let prices_path = args.prices;

    let profile_bytes_a: [u8; 2] = profile_a
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_a must be exactly 2 bytes, got {profile_a}"))?;
    let profile_bytes_b: [u8; 2] = profile_b
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_b must be exactly 2 bytes, got {profile_b}"))?;
    for (label, profile) in [(profile_a, &profile_bytes_a), (profile_b, &profile_bytes_b)] {
        if profile != b"v3" && profile != b"v4" {
            return Err(format!("unsupported venue {label:?}: expected v3 or v4"));
        }
    }

    let http_url: RedactedUrl = args
        .rpc
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let budget = ProviderBudget::new(40_000, 1 << 24);
    let retry = RetryPolicy {
        max_retries: 8,
        initial_delay: Duration::from_millis(600),
        max_delay: Duration::from_secs(12),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        4663,
    );

    let (a_entries, b_entries) = if let Some(path) = manifest_path {
        gaps::restrict_to_manifest(path, profile_bytes_a, profile_bytes_b)?
    } else {
        let catalog_a = gaps::load_catalog(a_path)?;
        let catalog_b = gaps::load_catalog(b_path)?;
        (
            catalog_a.into_values().collect::<Vec<_>>(),
            catalog_b.into_values().collect::<Vec<_>>(),
        )
    };
    if a_entries.is_empty() || b_entries.is_empty() {
        return Err(format!(
            "no pools for profiles v{} on both venues",
            profile_bytes_a[1]
        ));
    }
    let priced_a = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_a,
        pool_manager.unwrap_or(V4_POOL_MANAGER),
        &a_entries,
        from,
        to,
        window,
        Duration::from_millis(delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;
    let priced_b = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_b,
        pool_manager.unwrap_or(V4_POOL_MANAGER),
        &b_entries,
        from,
        to,
        window,
        Duration::from_millis(delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;
    let quotes = gaps::quote_manifest(&a_entries, &b_entries, &priced_a, &priced_b);

    // Feed the sweep into the dirty-set evaluator: each swept price is applied
    // as a local Swap event, marking only the pairs touched, then drained once
    // and classified through the conservative economics gate.
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: GAS_COST_USD,
        expected_win_rate: EXPECTED_WIN_RATE,
    };
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
    };
    let mut evaluator =
        dirty::PairDirtyEvaluator::new(&a_entries, &b_entries, economics, quotes.len().max(1));
    evaluator.set_reference(reference);
    evaluator.set_max_log2_skew(args.max_skew);
    if let Some(path) = prices_path {
        let prices = gaps::load_prices(path)?;
        println!(
            "loaded {} token prices from {}",
            prices.len(),
            path.display()
        );
        evaluator.set_token_prices(prices);
    }
    evaluator.seed_prices(profile_bytes_a, &a_entries, &priced_a)?;
    evaluator.seed_prices(profile_bytes_b, &b_entries, &priced_b)?;
    let dirty_depth = evaluator.queue_len();
    let outcome = evaluator.run_once();

    // Gate verdict on the single best quote, if any cleared the sweep.
    let top_verdict = quotes
        .first()
        .and_then(|quote| evaluator.quote_pair(gaps::pair_key(quote.token_lo, quote.token_hi)))
        .map(|(_, classification)| classification.reason);
    let verdict = top_verdict.map_or_else(|| "none".to_owned(), |reason| format!("{reason:?}"));

    println!(
        "quote-manifest: pools a={} b={} priced a={} b={} captureable={} gated={} dirty={} best={}",
        a_entries.len(),
        b_entries.len(),
        priced_a.len(),
        priced_b.len(),
        quotes.len(),
        outcome.interesting.len(),
        dirty_depth,
        verdict,
    );
    if let Some(path) = csv_path {
        let mut out =
            std::io::BufWriter::new(std::fs::File::create(path).map_err(|e| e.to_string())?);
        writeln!(out, "token_lo,token_hi,input,output,profit,toll,log2_skew")
            .map_err(|e| e.to_string())?;
        for quote in &quotes {
            writeln!(
                out,
                "{},{},{},{},{},{:.6},{:.6}",
                quote.token_lo,
                quote.token_hi,
                quote.input,
                quote.output,
                quote.profit,
                quote.toll,
                quote.log2_skew,
            )
            .map_err(|e| e.to_string())?;
        }
        println!("wrote {} quotes -> {}", quotes.len(), path.display());
    }
    Ok(())
}

/// Sweeps the USDG/WETH-anchored legs for the manifest's seed tokens and
/// derives a `token,usd_per_token` fixed-point price CSV from the median
/// reserve ratios. Read-only; no signing or submission.
#[allow(clippy::too_many_lines)]
fn derive_prices_command(args: &DerivePricesArgs<'_>) -> Result<(), String> {
    use std::io::Write;

    let profile_bytes_a: [u8; 2] = args
        .profile_a
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_a must be exactly 2 bytes, got {}", args.profile_a))?;
    let profile_bytes_b: [u8; 2] = args
        .profile_b
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_b must be exactly 2 bytes, got {}", args.profile_b))?;
    for (label, profile) in [
        (args.profile_a, &profile_bytes_a),
        (args.profile_b, &profile_bytes_b),
    ] {
        if profile != b"v3" && profile != b"v4" {
            return Err(format!("unsupported venue {label:?}: expected v3 or v4"));
        }
    }

    let http_url: RedactedUrl = args
        .rpc
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let budget = ProviderBudget::new(40_000, 1 << 24);
    let retry = RetryPolicy {
        max_retries: 8,
        initial_delay: Duration::from_millis(600),
        max_delay: Duration::from_secs(12),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        4663,
    );

    let catalog_a = gaps::load_catalog(args.a)?;
    let catalog_b = gaps::load_catalog(args.b)?;
    let (manifest_a, manifest_b) =
        gaps::restrict_to_manifest(args.manifest, profile_bytes_a, profile_bytes_b)?;
    if manifest_a.is_empty() || manifest_b.is_empty() {
        return Err("no seed pools for both venues in the manifest".to_owned());
    }

    // The seed token set is the manifest's distinct tokens (normalized), so
    // `usd_legs_for` only sweeps anchors touching our pairs.
    let mut seeds: HashSet<Address> = HashSet::new();
    for entry in manifest_a.iter().chain(manifest_b.iter()) {
        seeds.insert(entry.token0);
        seeds.insert(entry.token1);
    }
    let a_entries = catalog_a.into_values().collect::<Vec<_>>();
    let b_entries = catalog_b.into_values().collect::<Vec<_>>();
    let (legs_a, legs_b) = gaps::usd_legs_for(&a_entries, &b_entries, Some(&seeds));

    let priced_a = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_a,
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &legs_a,
        args.from,
        args.to,
        args.window,
        Duration::from_millis(args.delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;
    let priced_b = gaps::sweep_swap_prices(
        &reader,
        profile_bytes_b,
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &legs_b,
        args.from,
        args.to,
        args.window,
        Duration::from_millis(args.delay_ms),
        None,
    )
    .map_err(|e| e.to_string())?;

    let prices = gaps::derive_usd_prices(&legs_a, &legs_b, &priced_a, &priced_b);
    let mut out =
        std::io::BufWriter::new(std::fs::File::create(args.out).map_err(|e| e.to_string())?);
    writeln!(out, "token,usd_per_token").map_err(|e| e.to_string())?;
    let mut rows = prices.iter().collect::<Vec<_>>();
    rows.sort_by_key(|(token, _)| **token);
    for (token, usd) in rows {
        writeln!(out, "{token},{usd}").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())?;

    println!(
        "derive-prices: legs a={} b={} priced a={} b={} prices={} seeds={} -> {}",
        legs_a.len(),
        legs_b.len(),
        priced_a.len(),
        priced_b.len(),
        prices.len(),
        seeds.len(),
        args.out.display(),
    );
    Ok(())
}

/// `net_profit_usd / threshold_usd` as an f64 ratio (1.0 = at the submission
/// floor; real values here are quotients of USD fixed-point so the division is
/// exact). Returns `0.0` when the threshold is zero or empty.
fn floor_ratio(net: alloy_primitives::U256, threshold: alloy_primitives::U256) -> f64 {
    if threshold.is_zero() {
        return 0.0;
    }
    let n = gaps::f64_of(net);
    let t = gaps::f64_of(threshold);
    if t == 0.0 {
        return 0.0;
    }
    n / t
}

/// Arguments for [`run_pairs_command`].
struct RunPairsArgs<'a> {
    a: &'a PathBuf,
    b: &'a PathBuf,
    manifest: Option<&'a std::path::Path>,
    profile_a: &'a str,
    profile_b: &'a str,
    pool_manager: Option<Address>,
    rpc: &'a str,
    from: Option<u64>,
    poll_ms: u64,
    max_swaps: u64,
    duration_secs: u64,
    window: u64,
    delay_ms: u64,
    csv: Option<&'a std::path::Path>,
    prices: Option<&'a std::path::Path>,
    /// V3 address chunks swept per poll in the ring sweep; when zero the
    /// default covers the whole V3 universe within ~1h.
    v3_chunks_per_poll: u64,
    /// Maximum `|log2 skew|` a quote may carry and still be gated; quotes
    /// above it are screened out as uncaptureable.
    max_skew: f64,
    /// Maximum age in blocks (vs the poll tip) a quote's oldest leg price may
    /// carry and still be gated; `0` disables the screen.
    max_price_age: u64,
}

/// Polls Swap events from the chain tip and re-checks only the cross-venue
/// pairs touched by changed pools, draining each batch through the dirty-set
/// evaluator and the conservative economics gate. Read-only: prices are cached
/// locally from Swap logs, never `eth_call`ed per quote; nothing is submitted.
#[allow(clippy::too_many_lines)]
fn run_pairs_command(args: &RunPairsArgs<'_>) -> Result<(), String> {
    use std::io::Write;

    let a_path: &std::path::Path = args.a;
    let b_path: &std::path::Path = args.b;
    let manifest_path = args.manifest;
    let profile_a = args.profile_a;
    let profile_b = args.profile_b;
    let pool_manager: Option<Address> = args.pool_manager;
    let rpc_url = args.rpc;
    let from = args.from;
    let poll_ms = args.poll_ms;
    let max_swaps = args.max_swaps;
    let duration_secs = args.duration_secs;
    let window = args.window;
    let delay_ms = args.delay_ms;
    let csv_path = args.csv;
    let prices_path = args.prices;
    let mut csv_out: Option<std::io::BufWriter<std::fs::File>> = None;
    if let Some(path) = csv_path {
        let mut out =
            std::io::BufWriter::new(std::fs::File::create(path).map_err(|e| e.to_string())?);
        writeln!(
            out,
            "kind,token_lo,token_hi,to_block,input,output,profit,log2_skew,gross_profit_usd,net_profit_usd,threshold_usd,floor_ratio,reason"
        )
        .map_err(|e| e.to_string())?;
        csv_out = Some(out);
    }
    let profile_bytes_a: [u8; 2] = profile_a
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_a must be exactly 2 bytes, got {profile_a}"))?;
    let profile_bytes_b: [u8; 2] = profile_b
        .as_bytes()
        .try_into()
        .map_err(|_| format!("profile_b must be exactly 2 bytes, got {profile_b}"))?;
    for (label, profile) in [(profile_a, &profile_bytes_a), (profile_b, &profile_bytes_b)] {
        if profile != b"v3" && profile != b"v4" {
            return Err(format!("unsupported venue {label:?}: expected v3 or v4"));
        }
    }

    let http_url: RedactedUrl = rpc_url
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let budget = ProviderBudget::new(8_000_000, 1 << 24);
    let retry = RetryPolicy {
        max_retries: 8,
        initial_delay: Duration::from_millis(600),
        max_delay: Duration::from_secs(12),
    };
    let reader = ChainReader::new(
        LiveHttp::new(http_url.clone()),
        ThreadSleeper,
        budget.clone(),
        retry,
        4663,
    );

    let (a_entries, b_entries) = if let Some(path) = manifest_path {
        gaps::restrict_to_manifest(path, profile_bytes_a, profile_bytes_b)?
    } else {
        let catalog_a = gaps::load_catalog(a_path)?;
        let catalog_b = gaps::load_catalog(b_path)?;
        (
            catalog_a.into_values().collect::<Vec<_>>(),
            catalog_b.into_values().collect::<Vec<_>>(),
        )
    };
    if a_entries.is_empty() || b_entries.is_empty() {
        return Err(format!(
            "no pools for profiles v{} on both venues",
            profile_bytes_a[1]
        ));
    }

    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: GAS_COST_USD,
        expected_win_rate: EXPECTED_WIN_RATE,
    };
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
    };
    let queue_capacity = a_entries.len() + b_entries.len();
    let mut evaluator =
        dirty::PairDirtyEvaluator::new(&a_entries, &b_entries, economics, queue_capacity);
    evaluator.set_reference(reference);
    evaluator.set_max_log2_skew(args.max_skew);
    evaluator.set_max_price_age(args.max_price_age);
    if let Some(path) = prices_path {
        let prices = gaps::load_prices(path)?;
        println!(
            "loaded {} token prices from {}",
            prices.len(),
            path.display()
        );
        evaluator.set_token_prices(prices);
    }

    let start = match from {
        Some(block) => block,
        None => reader.current_block().map_err(|e| e.to_string())?,
    };
    let stop = StopOnSignal::install();
    let poll = Duration::from_millis(poll_ms);
    let delay = Duration::from_millis(delay_ms);
    let since = std::time::Instant::now();
    let mut high_water = start;
    let mut applied = 0u64;
    let mut evals = 0usize;
    let mut interesting = 0usize;
    let mut not_evaluated = 0usize;
    let mut triangle_evals = 0usize;
    let mut triangle_interesting = 0usize;
    let mut near_misses = 0usize;
    let mut last_window = 0u64;
    let v3_chunks = (a_entries.chunks(999).count() * usize::from(profile_bytes_a == *b"v3"))
        .max(b_entries.chunks(999).count() * usize::from(profile_bytes_b == *b"v3"))
        .max(1);
    // Default ring: sweep the whole V3 universe once per ~1h at the poll
    // cadence (chunks-per-poll = chunks × poll_ms / 3_600_000), so detection
    // latency stays under an hour while each poll burns one chunk of CU.
    let v3_chunks_per_poll_eff = if args.v3_chunks_per_poll == 0 {
        let per_hour = u64::try_from(v3_chunks)
            .expect("v3 catalog chunk count must fit u64")
            .saturating_mul(poll_ms)
            .saturating_div(3_600_000);
        per_hour.max(1)
    } else {
        args.v3_chunks_per_poll
    };
    let mut v3_ring_start = 0u64;

    loop {
        if stop.flag.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if max_swaps != 0 && applied >= max_swaps {
            break;
        }
        if duration_secs != 0 && since.elapsed().as_secs() >= duration_secs {
            eprintln!("run-pairs: duration reached after {duration_secs}s");
            break;
        }
        let latest = match reader.current_block() {
            Ok(block) => block,
            Err(TransportError::Transient(message)) => {
                eprintln!("run-pairs: transient error reading latest block; retrying: {message}");
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        if latest <= high_water {
            std::thread::sleep(poll);
            continue;
        }
        let window_from = high_water + 1;
        let v3_window = if profile_bytes_a == *b"v3" {
            Some((v3_ring_start, v3_chunks_per_poll_eff))
        } else {
            None
        };
        let priced_a = match gaps::sweep_swap_prices(
            &reader,
            profile_bytes_a,
            pool_manager.unwrap_or(V4_POOL_MANAGER),
            &a_entries,
            window_from,
            latest,
            window,
            delay,
            v3_window,
        ) {
            Ok(priced) => priced,
            Err(TransportError::Transient(message)) => {
                eprintln!("run-pairs: transient error sweeping profile A; retrying: {message}");
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let v4_window = if profile_bytes_b == *b"v3" {
            Some((v3_ring_start, v3_chunks_per_poll_eff))
        } else {
            None
        };
        let priced_b = match gaps::sweep_swap_prices(
            &reader,
            profile_bytes_b,
            pool_manager.unwrap_or(V4_POOL_MANAGER),
            &b_entries,
            window_from,
            latest,
            window,
            delay,
            v4_window,
        ) {
            Ok(priced) => priced,
            Err(TransportError::Transient(message)) => {
                eprintln!("run-pairs: transient error sweeping profile B; retrying: {message}");
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        // Advance the V3 ring cursor past the chunks swept this poll so every
        // pool is re-priced once per full ring.
        v3_ring_start = (v3_ring_start + v3_chunks_per_poll_eff) % v3_chunks as u64;
        let applied_this = priced_a.len() + priced_b.len();
        applied = applied.saturating_add(applied_this as u64);
        evaluator.seed_prices(profile_bytes_a, &a_entries, &priced_a)?;
        evaluator.seed_prices(profile_bytes_b, &b_entries, &priced_b)?;
        evaluator.set_current_block(latest);
        let outcome = evaluator.run_once();
        evals += outcome.evaluated.len();
        interesting += outcome.interesting.len();
        not_evaluated += outcome.not_evaluated.len();
        triangle_evals += outcome.triangle_evaluated.len();
        triangle_interesting += outcome.triangle_interesting.len();
        for pair in &outcome.evaluated {
            if let Some((_quote, classification)) = evaluator.quote_pair(*pair) {
                let ratio = floor_ratio(
                    classification.estimated_net_profit_usd,
                    classification.threshold_usd,
                );
                if (0.5..1.0).contains(&ratio) {
                    near_misses += 1;
                }
            }
        }
        for tri in &outcome.triangle_evaluated {
            if let Some((_quote, classification)) = evaluator.quote_triangle(*tri) {
                let ratio = floor_ratio(
                    classification.estimated_net_profit_usd,
                    classification.threshold_usd,
                );
                if (0.5..1.0).contains(&ratio) {
                    near_misses += 1;
                }
            }
        }
        if let Some(out) = &mut csv_out {
            for pair in &outcome.evaluated {
                if let Some((quote, classification)) = evaluator.quote_pair(*pair) {
                    let lo = alloy_primitives::Address::from_slice(&pair.0);
                    let hi = alloy_primitives::Address::from_slice(&pair.1);
                    writeln!(
                        out,
                        "pair,{},{},{},{},{},{},{:.6},{},{},{},{:.4},{:?}",
                        lo,
                        hi,
                        latest,
                        quote.input,
                        quote.output,
                        quote.profit,
                        quote.log2_skew,
                        classification.gross_profit_usd,
                        classification.estimated_net_profit_usd,
                        classification.threshold_usd,
                        floor_ratio(
                            classification.estimated_net_profit_usd,
                            classification.threshold_usd
                        ),
                        classification.reason,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
            for tri in &outcome.triangle_evaluated {
                if let Some((quote, classification)) = evaluator.quote_triangle(*tri) {
                    let t = evaluator.triangle(*tri);
                    let lo = alloy_primitives::Address::from_slice(&t.0);
                    let hi = alloy_primitives::Address::from_slice(&t.1);
                    writeln!(
                        out,
                        "triangle,{},{},{},{},{},{},{:.6},{},{},{},{:.4},{:?}",
                        lo,
                        hi,
                        latest,
                        quote.input,
                        quote.output,
                        quote.profit,
                        quote.log2_skew,
                        classification.gross_profit_usd,
                        classification.estimated_net_profit_usd,
                        classification.threshold_usd,
                        floor_ratio(
                            classification.estimated_net_profit_usd,
                            classification.threshold_usd
                        ),
                        classification.reason,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        last_window = latest;
        high_water = latest;
        println!(
            "run-pairs: poll {}-{} priced a={} b={} evals={} gated={} triangles={}/{} dirty={}",
            window_from,
            latest,
            priced_a.len(),
            priced_b.len(),
            outcome.evaluated.len(),
            outcome.interesting.len(),
            outcome.triangle_interesting.len(),
            outcome.triangle_evaluated.len(),
            outcome.not_evaluated.len(),
        );
        std::thread::sleep(poll);
    }

    let dirty_now = evaluator.queue_len();
    println!(
        "run-pairs: done at block {} applied={} evals={} gated={} triangles={}/{} near_miss={} not_evaluated={} dirty={} elapsed_s={}",
        last_window,
        applied,
        evals,
        interesting,
        triangle_interesting,
        triangle_evals,
        near_misses,
        not_evaluated,
        dirty_now,
        since.elapsed().as_secs(),
    );
    Ok(())
}

fn resolve_env_url(primary: &str, fallback: &str) -> Result<String, String> {
    std::env::var(primary)
        .or_else(|_| std::env::var(fallback))
        .map_err(|_| format!("missing {primary} (or fallback {fallback})"))
}

/// One WebSocket subscription slot: the planned filter plus its live client,
/// rolling stats, and reconnect backoff state.
struct WsProbeSlot {
    subscription: ws_probe::VenueSubscription,
    client: Option<LiveWsClient>,
    stats: ws_probe::ProbeStats,
    attempts: u32,
    retry_at: Option<Instant>,
}

impl WsProbeSlot {
    fn ensure_connected(&mut self, ws_url: &RedactedUrl) {
        if self.client.is_some() {
            return;
        }
        if self
            .retry_at
            .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return;
        }
        match LiveWsClient::connect(ws_url.clone(), self.subscription.filter.clone()) {
            Ok(client) => {
                self.client = Some(client);
                self.attempts = 0;
            }
            Err(_) => self.schedule_reconnect(),
        }
    }

    fn schedule_reconnect(&mut self) {
        self.client = None;
        self.stats.reconnects += 1;
        self.attempts += 1;
        self.retry_at = Some(Instant::now() + ws_probe::backoff_delay(self.attempts));
    }

    /// Connects if needed, drains one bounded item, and returns how many new
    /// events were counted.
    fn poll(
        &mut self,
        ws_url: &RedactedUrl,
        stream: &LogStream,
        timeout: Duration,
        tip: u64,
    ) -> usize {
        self.ensure_connected(ws_url);
        let Some(client) = self.client.as_ref() else {
            return 0;
        };
        match client.next(stream, timeout) {
            Ok(Some(StreamItem::Log(envelope))) => {
                if let Some(lag) = ws_probe::lag_or_skew(envelope.block_number, tip, 5) {
                    self.stats.observe_lag(lag);
                    1
                } else {
                    0
                }
            }
            Ok(Some(StreamItem::Disconnected(_))) | Err(_) => {
                self.schedule_reconnect();
                0
            }
            Ok(None) => 0,
        }
    }
}

fn merged_probe_stats(slots: &[WsProbeSlot]) -> ws_probe::ProbeStats {
    let mut window = ws_probe::ProbeStats::default();
    for slot in slots {
        window.merge(&slot.stats);
    }
    window
}

fn resolve_probe_endpoints() -> Result<(RedactedUrl, RedactedUrl), String> {
    let ws_endpoint = resolve_env_url("ALCHEMY_RHC_WS_URL", "ROBINHOOD_WS_RPC_URL")?;
    let http_endpoint = resolve_env_url("ALCHEMY_RHC_HTTP_URL", "ROBINHOOD_HTTP_RPC_URL")?;
    let ws_url = ws_endpoint
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let http_url = http_endpoint
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    Ok((ws_url, http_url))
}

fn run_ws_probe_command(
    manifest_path: &std::path::Path,
    duration_secs: u64,
    limit: u64,
    tip_interval_ms: u64,
    request_cu: u64,
    ws_bytes: u64,
) -> Result<(), String> {
    let (ws_url, http_url) = resolve_probe_endpoints()?;

    let (subscriptions, skipped) = ws_probe::build_subscriptions(
        fs::File::open(manifest_path).map_err(|error| error.to_string())?,
    )?;
    println!(
        "ws-probe: {} subscriptions ({} constant-product rows skipped), endpoint {}",
        subscriptions.len(),
        skipped,
        ws_url,
    );

    let budget = ProviderBudget::new(request_cu, ws_bytes);
    let stream = LogStream::new(budget.clone());
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

    let stop = StopOnSignal::install();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(duration_secs);
    let tip_interval = Duration::from_millis(tip_interval_ms.max(1_000));
    let poll_slice = Duration::from_millis(100);
    let mut tip = reader.current_block().map_err(|error| error.to_string())?;
    let mut last_tip_refresh = Instant::now();
    let mut next_progress = Instant::now() + Duration::from_secs(10);

    let mut slots: Vec<WsProbeSlot> = subscriptions
        .into_iter()
        .map(|subscription| WsProbeSlot {
            subscription,
            client: None,
            stats: ws_probe::ProbeStats::default(),
            attempts: 0,
            retry_at: None,
        })
        .collect();
    let mut total_events = 0u64;

    loop {
        if stop.flag.load(std::sync::atomic::Ordering::Relaxed)
            || Instant::now() >= deadline
            || (limit != 0 && total_events >= limit)
        {
            break;
        }
        if last_tip_refresh.elapsed() >= tip_interval {
            if let Ok(block) = reader.current_block() {
                tip = block;
            }
            last_tip_refresh = Instant::now();
        }
        for slot in &mut slots {
            total_events +=
                u64::try_from(slot.poll(&ws_url, &stream, poll_slice, tip)).unwrap_or(0);
        }
        if Instant::now() >= next_progress {
            let parts: Vec<String> = slots
                .iter()
                .map(|slot| {
                    format!(
                        "{}:events={}+r{}+maxlag{}",
                        slot.subscription.label,
                        slot.stats.events,
                        slot.stats.reconnects,
                        slot.stats.lag_max_blocks()
                    )
                })
                .collect();
            println!(
                "{} [{}]",
                ws_probe::progress_line(
                    started.elapsed().as_secs(),
                    &merged_probe_stats(&slots),
                    budget.snapshot().websocket_delivered_bytes,
                    tip,
                ),
                parts.join(" ")
            );
            next_progress += Duration::from_secs(10);
        }
    }

    let window = merged_probe_stats(&slots);
    let reason = if stop.flag.load(std::sync::atomic::Ordering::Relaxed) {
        "signal"
    } else if limit != 0 && total_events >= limit {
        "limit"
    } else {
        "duration"
    };
    print_probe_summary(started.elapsed().as_secs(), &window, reason, &budget);
    Ok(())
}

fn print_probe_summary(
    elapsed_secs: u64,
    window: &ws_probe::ProbeStats,
    reason: &str,
    budget: &ProviderBudget,
) {
    println!(
        "ws-probe: done elapsed_s={} events={} lag_blocks min/mean/max={}/{:.1}/{} reconnects={} reason={}",
        elapsed_secs,
        window.events,
        window
            .lag_min_blocks()
            .map_or("-".to_owned(), |min| min.to_string()),
        window
            .lag_mean_blocks()
            .map_or("-".to_owned(), |mean| format!("{mean:.1}")),
        window.lag_max_blocks(),
        window.reconnects,
        reason,
    );
    let usage = budget.snapshot();
    println!(
        "ws-probe: usage websocket_delivered_bytes={} websocket_accounted_bytes={} request_cu={} http_response_bytes={}",
        usage.websocket_delivered_bytes,
        usage.websocket_accounted_bytes,
        usage.request_cu,
        usage.http_response_bytes
    );
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
