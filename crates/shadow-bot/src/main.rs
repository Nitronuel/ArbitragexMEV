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
    ClassificationReason, CostSnapshot, Economics, FIXED_POINT_SCALE, ServiceReport,
    ServiceSnapshot, daily_report, observe_snapshot, replay_observation, run_live, run_smoke,
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

use shadow::gate_defaults::{
    STANDARD_EXPECTED_WIN_RATE as EXPECTED_WIN_RATE, STANDARD_GAS_COST_USD as GAS_COST_USD,
};

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
        /// Optional raw capture CSV (`recv_unix_ms,block,tx,log`) for offline
        /// lag analysis.
        #[arg(long)]
        raw_csv: Option<PathBuf>,
        /// A/B harness: HTTP getLogs sidecar poll interval in ms (0 = off).
        #[arg(long, default_value_t = 0)]
        ab_http_ms: u64,
        /// Optional A/B per-block comparison CSV (`block,ws_first_ms,
        /// http_first_ms,delta_ms`).
        #[arg(long)]
        ab_csv: Option<PathBuf>,
        /// Provider-comparison HTTP endpoint (URL or `env:VAR_NAME`) polled by
        /// a second sidecar; deltas reported against the primary HTTP view.
        #[arg(long)]
        bench_url: Option<String>,
        /// Bench sidecar poll interval in ms (0 = off).
        #[arg(long, default_value_t = 0)]
        bench_http_ms: u64,
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
    /// Ranks cross-venue pairs by observed Swap activity over a block window
    /// and writes a selection CSV consumable by `build-manifest` (read-only).
    RankActivity {
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
        /// Chain endpoint URL.
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
        /// Write the top N pairs ranked by two-sided swap activity.
        #[arg(long, default_value_t = 1000)]
        top: usize,
        /// Write each selected pair as one CSV row to this path (overwrites).
        #[arg(long)]
        csv: PathBuf,
    },
    /// Re-quotes one pinned-block capture against fresh chain reads and
    /// prints its make/loss ledger (read-only).
    VerifyCapture {
        /// Capture JSON written by `scripts/watch-gates.sh`.
        #[arg(long)]
        capture: PathBuf,
        /// Manifest scoping the sweep to the candidate pool set.
        #[arg(long)]
        manifest: PathBuf,
        /// v4 `PoolManager` contract address (only required when a profile is v4).
        #[arg(long)]
        pool_manager: Option<Address>,
        /// Chain endpoint URL.
        #[arg(long)]
        rpc: String,
        /// USD prices table (`derive-prices` output).
        #[arg(long)]
        prices: PathBuf,
        /// Gas spend per attempt, USD fixed-point.
        #[arg(long, default_value_t = U256::from(30_000_000_000_000_000_u64))]
        gas_usd: U256,
        /// Captured pair override (both required together) for captures
        /// written before watch-gates recorded `token_lo`/`token_hi`.
        #[arg(long)]
        token_lo: Option<Address>,
        /// Pair override, second half.
        #[arg(long)]
        token_hi: Option<Address>,
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
        /// Write one row per evaluated pair/triangle per poll to this path
        /// (appends; headers written on first open). Columns:
        /// `kind,token_lo,token_hi,to_block,input,output,profit,log2_skew`,
        /// `gross_profit_usd,net_profit_usd,shortfall_usd,threshold_usd`,
        /// `floor_ratio,optimal_unclamped,input_capacity,reason_code`,
        /// `reason_detail,anchor_priced`. `shortfall_usd` measures how far
        /// below the gate floor a near-miss fell (audit E4); `reason_code`
        /// is a stable machine token with human context in the quoted
        /// `reason_detail` (audit A18). Appends across restarts. The two
        /// capacity columns expose the audit-S1 clamp: what the model wanted
        /// to trade vs. what one tick-spacing cell can absorb.
        /// expose the audit-S1 single-tick capacity clamp: what the model
        /// wanted to trade vs. what one tick-spacing cell can absorb. `anchor_priced=false` marks rows whose USD value
        /// came from the `$1` fixture because the anchor token was absent
        /// (or zero) in the `--prices` table; a gate pass on such a row is
        /// classified `Provisional`, never counted as an honest candidate.
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Token-price CSV (`token,usd_per_token`, fixed-point) for honest
        /// USD gating instead of the `$1` fixture.
        #[arg(long)]
        prices: Option<PathBuf>,
        /// V3 catalog address-chunks swept per poll in the ring sweep. The
        /// most-behind chunks go first; every chunk carries its own
        /// high-water mark, so no block is ever skipped regardless of this
        /// cadence — it trades CU burn against detection latency only.
        /// `0` sweeps all chunks (whole universe) every poll.
        #[arg(long, default_value_t = 1)]
        v3_chunks_per_poll: u64,
        /// Confirmation lag: sweep up to this many blocks behind the tip so
        /// reorged-out logs are never applied as canonical. Coverage is
        /// stamped at the lagged block, not the tip.
        #[arg(long, default_value_t = 10)]
        confirm_lag_blocks: u64,
        /// Capacity-overshoot bound: a quote whose unclamped optimal input
        /// exceeds every leg's single-tick liquidity capacity by more than
        /// this factor is screened instead of gated (audit S1).
        #[arg(long, default_value_t = dirty::DEFAULT_MAX_CAPACITY_OVERSHOOT)]
        max_capacity_overshoot: f64,
        /// USD value of one whole native token (fixed-point), converting the
        /// live gas price into the gate's cost side. Defaults to $1 — a
        /// placeholder until the chain's native price is supplied; the loop
        /// prints a warning whenever the default is in effect.
        #[arg(long, default_value_t = U256::from(shadow::FIXED_POINT_SCALE))]
        native_usd: U256,
        /// Maximum age (seconds) of the cached gas price before the gate
        /// fails closed. The price is re-read on this cadence (~10 CU).
        #[arg(long, default_value_t = 120)]
        gas_price_max_age_secs: u64,
        /// Request-CU ceiling for this invocation. Audit A13: previously a
        /// hardcoded 8M unknown to the operator while other subcommands used
        /// different values; month-to-date persistence lands with task 4.3.
        #[arg(long, default_value_t = 8_000_000)]
        request_cu_ceiling: u64,
        /// Maximum `|log2 skew|` a quote may carry and still be gated.
        /// Larger gaps come from degenerate near-empty pools that are not
        /// captureable; they are screened out instead of surfacing as
        /// `AboveThreshold` at meaningless USD values.
        #[arg(long, default_value_t = 0.5)]
        max_skew: f64,
        /// Flash-loan source for gating costs: `none` (legacy zero-fee
        /// assumption), a provider name (`balancer-v2`, `uniswap-v4`,
        /// `aave-v3`), or `auto` to pick the cheapest supporting provider per
        /// anchor token from `--flash-support`. In `auto` mode an anchor with
        /// no supporting provider is screened out instead of gated.
        #[arg(long, default_value = "none")]
        flash_provider: String,
        /// Support CSV (`token,provider`) mapping each anchor token to the
        /// flash-loan providers that can serve it. Required by
        /// `--flash-provider auto`.
        #[arg(long)]
        flash_support: Option<PathBuf>,
        /// Backstop age bound: a cached price this many blocks behind the tip
        /// screens the quote even when sweep coverage claims continuity (0
        /// disables the age backstop; coverage screening always applies).
        #[arg(long, default_value_t = dirty::DEFAULT_MAX_LEG_AGE_BLOCKS)]
        max_leg_age_blocks: u64,
        /// Maximum `|block_a - block_b|` across the priced candidate pools of
        /// one quote; wider spreads compose leg prices from disjoint market
        /// states and are screened instead of gated.
        #[arg(long, default_value_t = dirty::DEFAULT_MAX_LEG_AGE_SPREAD_BLOCKS)]
        max_leg_age_spread_blocks: u64,
    },
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::ValidateConfig { config } => validate_config(&config),
        Command::VerifyCatalog { manifest, config } => verify_catalog_command(manifest, config),
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
            raw_csv,
            ab_http_ms,
            ab_csv,
            bench_url,
            bench_http_ms,
        } => run_ws_probe_command(
            &manifest,
            duration_secs,
            limit,
            tip_interval_ms,
            request_cu,
            ws_bytes,
            ProbeOutputs {
                raw_csv: raw_csv.as_deref(),
                ab_http_ms,
                ab_csv: ab_csv.as_deref(),
                bench_url: bench_url.as_deref(),
                bench_http_ms,
            },
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
        Command::RankActivity {
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
            csv,
        } => rank_activity_command(&RankActivityArgs {
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
            csv: &csv,
        }),
        Command::VerifyCapture {
            capture,
            manifest,
            pool_manager,
            rpc,
            prices,
            gas_usd,
            token_lo,
            token_hi,
        } => verify_capture_command(&VerifyCaptureArgs {
            capture: &capture,
            manifest: &manifest,
            pool_manager,
            rpc: &rpc,
            prices: &prices,
            gas_usd,
            token_lo,
            token_hi,
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
            confirm_lag_blocks,
            max_capacity_overshoot,
            native_usd,
            gas_price_max_age_secs,
            request_cu_ceiling,
            max_skew,
            flash_provider,
            flash_support,
            max_leg_age_blocks,
            max_leg_age_spread_blocks,
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
            confirm_lag_blocks,
            max_capacity_overshoot,
            native_usd,
            gas_price_max_age_secs,
            request_cu_ceiling,
            max_skew,
            flash_provider: &flash_provider,
            flash_support: flash_support.as_deref(),
            max_leg_age_blocks,
            max_leg_age_spread_blocks,
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
/// statically. No RPC calls are made.
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
    // Audit A13 (debt, task 4.3): hardcoded per-command budget; month-to-date
    // persistence and ShadowConfig sourcing are pending.
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
///
/// Offline ranking tool: applies its own `--max-skew` bound but bypasses the
/// dirty evaluator's price-age screen, so its rows may carry refresh-starved
/// legs — unlike `run-pairs`, its output is not gate evidence.
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
    // Audit A13 (debt, task 4.3): hardcoded per-command budget; month-to-date
    // persistence and ShadowConfig sourcing are pending.
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
        domain::ROBINHOOD_CHAIN_ID,
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

/// Arguments for [`rank_activity_command`].
struct RankActivityArgs<'a> {
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
    csv: &'a std::path::Path,
}

/// Ranks cross-venue pairs by observed Swap activity over a block window and
/// writes a `build-manifest`-consumable selection CSV. Read-only; no signing
/// or submission.
///
/// Selection by two-sided activity (`min` of the per-venue counts) maximizes
/// how often the live poller can actually evaluate each pair, since a pair is
/// only quotable while both venues carry a swap-priced leg.
#[allow(clippy::too_many_lines)]
fn rank_activity_command(args: &RankActivityArgs<'_>) -> Result<(), String> {
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
    if args.from > args.to {
        return Err("--from must not exceed --to".to_owned());
    }

    let catalog_a = gaps::load_catalog(args.a)?;
    let catalog_b = gaps::load_catalog(args.b)?;
    let (cross_a, cross_b) = gaps::restrict_to_cross(&catalog_a, &catalog_b);
    println!(
        "rank-activity: catalogs a={} b={} cross a={} b={}",
        catalog_a.len(),
        catalog_b.len(),
        cross_a.len(),
        cross_b.len()
    );

    let http_url: RedactedUrl = args
        .rpc
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    // Audit A13 (debt, task 4.3): hardcoded per-command budget; month-to-date
    // persistence and ShadowConfig sourcing are pending.
    let budget = ProviderBudget::new(2_000_000, 1 << 24);
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
        domain::ROBINHOOD_CHAIN_ID,
    );

    let activity_a = gaps::sweep_swap_activity(
        &reader,
        profile_bytes_a,
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &cross_a,
        args.from,
        args.to,
        args.window,
        Duration::from_millis(args.delay_ms),
    )
    .map_err(|e| e.to_string())?;
    let activity_b = gaps::sweep_swap_activity(
        &reader,
        profile_bytes_b,
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &cross_b,
        args.from,
        args.to,
        args.window,
        Duration::from_millis(args.delay_ms),
    )
    .map_err(|e| e.to_string())?;
    let active_a = activity_a.len();
    let active_b = activity_b.len();
    let rankings = gaps::pair_activity_rankings(&cross_a, &cross_b, &activity_a, &activity_b);
    let two_sided_pairs = rankings.len();
    let selected: Vec<_> = rankings.into_iter().take(args.top).collect();
    if selected.is_empty() {
        return Err(
            "no cross-venue pair saw swaps on both venues in the window; \
             widen --from/--to"
                .to_owned(),
        );
    }

    let mut out =
        std::io::BufWriter::new(std::fs::File::create(args.csv).map_err(|e| e.to_string())?);
    writeln!(out, "token_lo,token_hi,swaps_a,swaps_b,score").map_err(|e| e.to_string())?;
    for ranking in &selected {
        writeln!(
            out,
            "{},{},{},{},{}",
            ranking.token_lo, ranking.token_hi, ranking.swaps_a, ranking.swaps_b, ranking.score
        )
        .map_err(|e| e.to_string())?;
    }
    println!(
        "rank-activity: active pools a={} b={} pairs_two_sided={} wrote_top_{} -> {}",
        active_a,
        active_b,
        two_sided_pairs,
        selected.len(),
        args.csv.display()
    );
    Ok(())
}

/// Arguments for [`verify_capture_command`].
struct VerifyCaptureArgs<'a> {
    capture: &'a PathBuf,
    manifest: &'a PathBuf,
    pool_manager: Option<Address>,
    rpc: &'a str,
    prices: &'a PathBuf,
    gas_usd: U256,
    /// Captured pair override (`--token-lo`/`--token-hi`), for captures
    /// written before `watch-gates.sh` recorded the pair. Either both or
    /// neither.
    token_lo: Option<Address>,
    token_hi: Option<Address>,
}

/// Re-quotes one pinned capture against fresh chain reads and prints its
/// make/loss ledger. Read-only; no signing or submission.
///
/// The capture's `tip_block` pins every read, so the re-quote sees the same
/// state the live evaluator raced against — within the gateway's 60–120
/// minute history horizon (capture promptly).
#[allow(clippy::too_many_lines)]
fn verify_capture_command(args: &VerifyCaptureArgs<'_>) -> Result<(), String> {
    let raw = std::fs::read_to_string(args.capture).map_err(|e| e.to_string())?;
    let capture: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("malformed capture: {e}"))?;
    let block = capture["tip_block"]
        .as_u64()
        .ok_or("capture lacks tip_block")?;
    let gated = capture["gated"].as_u64().unwrap_or(0);
    println!("verify-capture: pinned block {block} ({gated} gate-passing rows at detection)");

    let http_url: RedactedUrl = args
        .rpc
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    // Audit A13 (debt, task 4.3): hardcoded per-command budget; month-to-date
    // persistence and ShadowConfig sourcing are pending.
    let budget = ProviderBudget::new(200_000, 1 << 24);
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
        domain::ROBINHOOD_CHAIN_ID,
    );

    let (manifest_v3, manifest_v4) = gaps::restrict_to_manifest(args.manifest, *b"v3", *b"v4")?;
    if manifest_v3.is_empty() || manifest_v4.is_empty() {
        return Err("manifest has no pools for one of the venues".to_owned());
    }

    // Resolve the captured pair. The re-quote must price the opportunity the
    // canary actually recorded — previously this command passed the whole
    // manifest to quote_pair, whose best-leg picked two unrelated pools and
    // reported P&L for a cycle that did not exist (audit finding S7).
    let capture_lo = capture["token_lo"].as_str();
    let capture_hi = capture["token_hi"].as_str();
    let (lo, hi) = match (capture_lo, capture_hi, args.token_lo, args.token_hi) {
        (Some(lo), Some(hi), _, _) => (
            lo.parse::<Address>()
                .map_err(|e| format!("capture token_lo malformed: {e}"))?,
            hi.parse::<Address>()
                .map_err(|e| format!("capture token_hi malformed: {e}"))?,
        ),
        (None, None, Some(lo), Some(hi)) => (lo, hi),
        (Some(_), None, _, _) | (None, Some(_), _, _) => {
            return Err("capture has only one of token_lo/token_hi".to_owned());
        }
        (_, _, Some(_), None) | (_, _, None, Some(_)) => {
            return Err("--token-lo and --token-hi must be passed together".to_owned());
        }
        (None, None, None, None) => {
            return Err(
                "capture lacks token_lo/token_hi (pre-0.3 watch-gates format); \
                 pass --token-lo/--token-hi from the canary CSV's gated row"
                    .to_owned(),
            );
        }
    };
    let want = gaps::pair_key(lo, hi);
    let scoped_pair = |entries: &[gaps::PoolEntry]| -> Vec<gaps::PoolEntry> {
        entries
            .iter()
            .filter(|e| gaps::pair_key(e.token0, e.token1) == want)
            .copied()
            .collect()
    };
    let legs_a = scoped_pair(&manifest_v3);
    let legs_b = scoped_pair(&manifest_v4);
    if legs_a.is_empty() || legs_b.is_empty() {
        return Err(format!(
            "captured pair {lo:#}/{hi:#} is absent from the manifest on \
             at least one venue; cannot re-quote"
        ));
    }
    println!(
        "verify-capture: captured pair {:#} / {:#} ({} v3 pools, {} v4 pools)",
        Address::from_slice(&want.0),
        Address::from_slice(&want.1),
        legs_a.len(),
        legs_b.len()
    );

    // Re-read chain truth at the pinned block: latest Swap-implied price per
    // leg within the lookback window.
    let from = block.saturating_sub(72_000);
    let prices_a = gaps::sweep_swap_prices(
        &reader,
        *b"v3",
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &legs_a,
        from,
        block,
        1000,
        Duration::from_millis(400),
        None,
    )
    .map_err(|e| e.to_string())?;
    let prices_b = gaps::sweep_swap_prices(
        &reader,
        *b"v4",
        args.pool_manager.unwrap_or(V4_POOL_MANAGER),
        &legs_b,
        from,
        block,
        1000,
        Duration::from_millis(400),
        None,
    )
    .map_err(|e| e.to_string())?;

    // Anchor price from the table; a missing anchor is fail-closed.
    println!(
        "verify-capture: re-read prices a={} b={}",
        prices_a.len(),
        prices_b.len()
    );
    let table = gaps::load_prices(args.prices)?;
    let entries_a: Vec<_> = legs_a.clone();
    let entries_b: Vec<_> = legs_b.clone();
    let Some(quote) = gaps::quote_pair(&entries_a, &entries_b, &prices_a, &prices_b)? else {
        return Err("no priced leg on both venues at the pinned block".to_owned());
    };
    let usd_per_anchor = *table
        .get(&quote.token_lo)
        .ok_or_else(|| format!("anchor {} unpriced in the table", quote.token_lo))?;
    if usd_per_anchor.is_zero() {
        return Err(format!("anchor {} priced at zero", quote.token_lo));
    }

    let ledger = gaps::verify_capture_ledger(
        &entries_a,
        &entries_b,
        &prices_a,
        &prices_b,
        quote.token_lo,
        usd_per_anchor,
        args.gas_usd,
    )?;

    let scale = U256::from(shadow::FIXED_POINT_SCALE);
    let fmt_usd = |v: U256| {
        let whole = v / scale;
        let frac = (v % scale) * U256::from(1000) / scale;
        format!("${}.{:03}", whole, u64::try_from(frac).unwrap_or(999))
    };
    println!(
        "verify-capture: pair {} :: {}",
        ledger.token_lo, ledger.token_hi
    );
    println!(
        "verify-capture: optimal input={} output={} profit={} tokens (skew {:.4})",
        ledger.input, ledger.output, ledger.profit, ledger.log2_skew
    );
    println!(
        "verify-capture: net with free flash loan {} | net with Aave 0.05% {}",
        fmt_usd(ledger.net_usd_none),
        fmt_usd(ledger.net_usd_aave)
    );
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
        native_token_usd: U256::from(FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    };
    // Audit S4: the validity flags are computed, not pinned. The gas price is
    // read once here (~10 CU); "reference current" means a USD table was
    // actually loaded — without it every anchor is $1-fixture priced.
    let (gas_price_wei, gas_ok) = match reader.gas_price() {
        Ok(wei) => (wei, true),
        Err(error) => {
            eprintln!("quote-manifest: gas-price read failed; gate fails closed: {error}");
            (U256::ZERO, false)
        }
    };
    let mut loaded_prices = 0usize;
    if let Some(path) = prices_path {
        let prices = gaps::load_prices(path)?;
        loaded_prices = prices.len();
        println!(
            "loaded {loaded_prices} token prices from {}",
            path.display()
        );
    }
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: gas_ok,
        reference_price_valid: loaded_prices > 0,
        gas_price_wei,
    };
    let mut evaluator =
        dirty::PairDirtyEvaluator::new(&a_entries, &b_entries, economics, quotes.len().max(1));
    evaluator.set_reference(reference);
    evaluator.set_max_log2_skew(args.max_skew);
    if let Some(path) = prices_path {
        let prices = gaps::load_prices(path)?;
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

    // The whole derivation hangs on the USDG decimals constant: every price
    // scales by `10^(36-d_usdg)`, so a wrong constant shifts the entire table
    // uniformly (and silently re-prices every gate). Verify it on-chain,
    // fail-closed, before writing anything.
    let decimals_data = reader
        .call(
            gaps::RHC_USDG,
            &alloy_primitives::Bytes::from(vec![0x31, 0x3c, 0xe5, 0x67]),
            args.to,
        )
        .map_err(|e| format!("USDG decimals() call failed: {e}"))?;
    let usdg_decimals = gaps::decode_word_decimals(&decimals_data)
        .ok_or("USDG decimals() returned malformed data")?;
    if usdg_decimals != gaps::RHC_USDG_DECIMALS {
        return Err(format!(
            "on-chain USDG decimals() = {usdg_decimals} but RHC_USDG_DECIMALS = {} \
             — price derivation constants are stale; update before deriving",
            gaps::RHC_USDG_DECIMALS
        ));
    }

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

/// Builds the flash-loan cost selection from CLI arguments.
///
/// `auto` reads the support CSV (`token,provider` rows) and fails closed at
/// startup if it is missing — without support data nothing can be gated.
fn build_flash_selection(
    mode: &str,
    support: Option<&std::path::Path>,
) -> Result<shadow::flash_loan::FlashSelection, String> {
    use shadow::flash_loan::{FlashLoanProvider, FlashSelection};
    match mode {
        "none" => Ok(FlashSelection::None),
        "auto" => {
            let Some(path) = support else {
                return Err(
                    "--flash-provider auto requires --flash-support <token,provider CSV>".to_owned(),
                );
            };
            let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
            let mut reader = csv::Reader::from_reader(file);
            let mut rows = Vec::new();
            for record in reader.records() {
                let record = record.map_err(|e| e.to_string())?;
                // Tokens are normalized exactly like every quote-path anchor
                // (audit A10): the V4 native sentinel maps to RHC_NATIVE, so
                // a support row written with the zero address actually covers
                // native-anchored routes instead of never matching.
                let raw_token = record
                    .get(0)
                    .ok_or_else(|| "support row lacks token".to_owned())?
                    .parse::<Address>()
                    .map_err(|_| "bad token in support row".to_owned())?;
                let token = gaps::normalize_currency(raw_token);
                let provider = record
                    .get(1)
                    .ok_or_else(|| "support row lacks provider".to_owned())?;
                if FlashLoanProvider::parse(provider).is_none() {
                    return Err(format!(
                        "unknown flash provider {provider:?} in support row (expected one of: {})",
                        FlashLoanProvider::ALL
                            .iter()
                            .map(|p| p.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                rows.push((token, provider.to_owned()));
            }
            println!(
                "flash-support: {} rows from {}",
                rows.len(),
                path.display()
            );
            if rows.is_empty() {
                // Audit A10: an empty support set silently gated nothing for a
                // whole canary while looking like "no opportunities". Fail the
                // invocation instead of shipping a measurement that cannot gate.
                return Err(format!(
                    "flash-support file {} parsed to zero usable rows; \
                     auto mode would screen every quote",
                    path.display()
                ));
            }
            Ok(FlashSelection::auto_from_rows(&rows))
        }
        other => FlashLoanProvider::parse(other)
            .map(FlashSelection::Fixed)
            .ok_or_else(|| format!("unknown --flash-provider {other:?} (expected none, auto, balancer-v2, uniswap-v4, aave-v3)")),
    }
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
    /// V3 address chunks swept per poll in the ring sweep (0 = all chunks).
    v3_chunks_per_poll: u64,
    /// Confirmation lag behind the chain tip for sweeps and coverage.
    confirm_lag_blocks: u64,
    /// Maximum `|log2 skew|` a quote may carry and still be gated; quotes
    /// above it are screened out as uncaptureable.
    max_skew: f64,
    /// Flash-loan cost mode for gating (`none`, a provider name, or `auto`).
    flash_provider: &'a str,
    /// Support CSV backing `flash_provider = auto`.
    flash_support: Option<&'a std::path::Path>,
    /// Backstop age bound for cached leg prices (blocks behind the tip).
    max_leg_age_blocks: u64,
    /// Maximum block spread across one quote's priced candidate pools.
    max_leg_age_spread_blocks: u64,
    /// Capacity-overshoot factor above which quotes are screened.
    max_capacity_overshoot: f64,
    /// USD per whole native token for gas conversion.
    native_usd: U256,
    /// Gas-price staleness bound (seconds).
    gas_price_max_age_secs: u64,
    /// Request-CU ceiling for this invocation.
    request_cu_ceiling: u64,
}

/// Polls Swap events from the chain tip and re-checks only the cross-venue
/// pairs touched by changed pools, draining each batch through the dirty-set
/// evaluator and the conservative economics gate. Read-only: prices are cached
/// locally from Swap logs, never `eth_call`ed per quote; nothing is submitted.
#[allow(clippy::too_many_lines)]
fn run_pairs_command(args: &RunPairsArgs<'_>) -> Result<(), String> {
    use std::io::Write;

    if args.window == 0 {
        return Err("--window must be at least 1 block".to_owned());
    }
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
        // Audit A14: append, never truncate — every restart previously
        // destroyed all prior evidence despite the docs claiming append.
        let existed = matches!(path.metadata(), Ok(meta) if meta.len() > 0);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let mut out = std::io::BufWriter::new(file);
        if !existed {
            writeln!(
                out,
                "kind,token_lo,token_hi,to_block,input,output,profit,log2_skew,gross_profit_usd,net_profit_usd,shortfall_usd,threshold_usd,floor_ratio,optimal_unclamped,input_capacity,reason_code,reason_detail,anchor_priced"
            )
            .map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
        }
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
    let budget = ProviderBudget::new(args.request_cu_ceiling, 1 << 24);
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
        native_token_usd: U256::from(FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    };
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
        gas_price_wei: U256::ZERO,
    };
    let queue_capacity = a_entries.len() + b_entries.len();
    let mut evaluator =
        dirty::PairDirtyEvaluator::new(&a_entries, &b_entries, economics, queue_capacity);
    evaluator.set_reference(reference);
    // Live gas-price state for the cost model (audit S4): fetched on a
    // cadence bounded by --gas-price-max-age-secs; a failed or stale read
    // fails the gate closed through CostSnapshot::gas_price_age_valid.
    let gas_max_age = Duration::from_secs(args.gas_price_max_age_secs.max(1));
    let mut gas_state: Option<(U256, std::time::Instant)> = None;
    if args.native_usd == U256::from(FIXED_POINT_SCALE) {
        eprintln!(
            "run-pairs: WARNING --native-usd defaults to $1; gas costs are              placeholders until the native price is supplied"
        );
    }
    let prices_loaded = prices_path.is_some();
    evaluator.set_max_log2_skew(args.max_skew);
    let flash_selection = build_flash_selection(args.flash_provider, args.flash_support)?;
    if matches!(flash_selection, shadow::flash_loan::FlashSelection::None)
        && args.flash_provider == "none"
    {
        eprintln!(
            "run-pairs: WARNING --flash-provider none assumes free capital; \
             gating ignores borrow fees (measurement mode only)"
        );
    }
    evaluator.set_flash_selection(flash_selection);
    evaluator.set_staleness_bounds(args.max_leg_age_blocks, args.max_leg_age_spread_blocks);
    evaluator.set_max_capacity_overshoot(args.max_capacity_overshoot);
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
    let mut applied = 0u64;
    let mut evals = 0usize;
    let mut interesting = 0usize;
    let mut not_evaluated = 0usize;
    let mut stale_screened = 0usize;
    let mut triangle_evals = 0usize;
    let mut triangle_interesting = 0usize;
    let mut near_misses = 0usize;
    let mut provisionals = 0usize;
    let mut last_window = 0u64;
    // Per-chunk high-water marks: chunk c is observed through water[c]. Each
    // poll sweeps the most-behind chunks and advances only their marks, so
    // ring-skipped chunks keep their position instead of silently losing the
    // block range (the S2a data-loss defect). V4 sweeps as one pseudo-chunk.
    let mut water_a =
        vec![start.saturating_sub(1); gaps::sweep_chunk_count(profile_bytes_a, &a_entries)];
    let mut water_b =
        vec![start.saturating_sub(1); gaps::sweep_chunk_count(profile_bytes_b, &b_entries)];
    let v3_chunks_per_poll_eff = usize::try_from(args.v3_chunks_per_poll).unwrap_or(usize::MAX);

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
        // Sweep up to the confirmation-lagged tip: reorged-out logs are
        // never applied as canonical, and coverage is stamped at the lagged
        // block, not the raw tip.
        let to_eff = latest.saturating_sub(args.confirm_lag_blocks);
        let sweep_a = match gaps::sweep_swap_prices_ring(
            &reader,
            profile_bytes_a,
            pool_manager.unwrap_or(V4_POOL_MANAGER),
            &a_entries,
            &mut water_a,
            start.saturating_sub(1),
            v3_chunks_per_poll_eff,
            to_eff,
            window,
            delay,
            gaps::DEFAULT_MAX_CATCHUP_BLOCKS,
        ) {
            Ok(outcome) => outcome,
            Err(TransportError::Transient(message)) => {
                eprintln!("run-pairs: transient error sweeping venue A; retrying: {message}");
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let sweep_b = match gaps::sweep_swap_prices_ring(
            &reader,
            profile_bytes_b,
            pool_manager.unwrap_or(V4_POOL_MANAGER),
            &b_entries,
            &mut water_b,
            start.saturating_sub(1),
            v3_chunks_per_poll_eff,
            to_eff,
            window,
            delay,
            gaps::DEFAULT_MAX_CATCHUP_BLOCKS,
        ) {
            Ok(outcome) => outcome,
            Err(TransportError::Transient(message)) => {
                eprintln!("run-pairs: transient error sweeping venue B; retrying: {message}");
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(error.to_string()),
        };
        let priced_a = sweep_a.prices;
        let covered_a = sweep_a.covered_keys;
        let priced_b = sweep_b.prices;
        let covered_b = sweep_b.covered_keys;
        let applied_this = priced_a.len() + priced_b.len();
        applied = applied.saturating_add(applied_this as u64);
        evaluator.invalidate_prices(profile_bytes_a, &sweep_a.invalidated_keys);
        evaluator.invalidate_prices(profile_bytes_b, &sweep_b.invalidated_keys);
        evaluator.seed_prices(profile_bytes_a, &a_entries, &priced_a)?;
        evaluator.seed_prices(profile_bytes_b, &b_entries, &priced_b)?;
        // Stamp sweep coverage *after* both sweeps succeeded. The ring
        // outcome reports exactly which pools were observed through which
        // block (catch-up capping can leave chunks at different depths);
        // pools in chunks not selected this poll keep their old voucher and
        // their pairs screen stale until their chunk comes around.
        evaluator.set_tip(to_eff);
        evaluator.mark_swept_keys(profile_bytes_a, &covered_a);
        evaluator.mark_swept_keys(profile_bytes_b, &covered_b);

        // Refresh the gas price when its cache ages past the bound. A read
        // failure keeps the old value, which then goes stale naturally and
        // fails the gate closed (audit S4: no more pinned-open validity).
        if gas_state.is_none_or(|(_, at)| at.elapsed() >= gas_max_age) {
            match reader.gas_price() {
                Ok(price_wei) => gas_state = Some((price_wei, std::time::Instant::now())),
                Err(TransportError::Transient(message)) => {
                    eprintln!("run-pairs: transient gas-price read; keeping cache: {message}");
                }
                Err(error) => {
                    eprintln!("run-pairs: gas-price read failed; keeping cache: {error}");
                }
            }
        }
        let (gas_price_wei, gas_age_valid) = match gas_state {
            Some((wei, at)) => (wei, at.elapsed() < gas_max_age),
            None => (U256::ZERO, false),
        };
        evaluator.set_reference(CostSnapshot {
            usd_per_token: U256::from(FIXED_POINT_SCALE),
            // Honest proxy for "reference route current": the USD table was
            // actually loaded — without it every anchor is $1-fixture priced
            // and gating is meaningless (audit S4).
            reference_price_valid: prices_loaded,
            gas_price_age_valid: gas_age_valid,
            gas_price_wei,
        });
        let outcome = evaluator.run_once();
        if !outcome.stale_screened.is_empty() || !outcome.triangle_stale_screened.is_empty() {
            eprintln!(
                "run-pairs: screened {} pair(s), {} triangle(s) on broken sweep coverage or leg age",
                outcome.stale_screened.len(),
                outcome.triangle_stale_screened.len()
            );
        }
        // One line per gate-passing row, carrying the pair identity: this is
        // what watch-gates.sh parses into capture files, so verify-capture
        // can re-quote the recorded opportunity instead of an arbitrary pair.
        for (_pair, (quote, classification)) in outcome.evaluated.iter().zip(&outcome.pair_results)
        {
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                // Print the quote's CHOSEN anchor (task 0.6), which need not
                // match canonical pair order.
                println!(
                    "run-pairs: GATED pair token_lo={} token_hi={} net_usd={} threshold_usd={} floor_ratio={:.4}",
                    quote.token_lo,
                    quote.token_hi,
                    classification.estimated_net_profit_usd,
                    classification.threshold_usd,
                    floor_ratio(
                        classification.estimated_net_profit_usd,
                        classification.threshold_usd
                    ),
                );
            }
        }
        for (tri, (quote, classification)) in outcome
            .triangle_evaluated
            .iter()
            .zip(&outcome.triangle_results)
        {
            if matches!(classification.reason, ClassificationReason::AboveThreshold) {
                let t = evaluator.triangle(*tri);
                println!(
                    "run-pairs: GATED triangle tokens={},{},{} skew={:.6} net_usd={} floor_ratio={:.4}",
                    Address::from_slice(&t.0),
                    Address::from_slice(&t.1),
                    Address::from_slice(&t.2),
                    quote.log2_skew,
                    classification.estimated_net_profit_usd,
                    floor_ratio(
                        classification.estimated_net_profit_usd,
                        classification.threshold_usd
                    ),
                );
            }
        }
        if outcome.degraded {
            eprintln!(
                "run-pairs: dirty queue exceeded capacity; some pairs were dropped this batch"
            );
        }
        evals += outcome.evaluated.len();
        interesting += outcome.interesting.len();
        not_evaluated += outcome.not_evaluated.len();
        stale_screened += outcome.stale_screened.len() + outcome.triangle_stale_screened.len();
        triangle_evals += outcome.triangle_evaluated.len();
        triangle_interesting += outcome.triangle_interesting.len();
        near_misses += outcome
            .pair_results
            .iter()
            .chain(&outcome.triangle_results)
            .filter(|(_, classification)| {
                let ratio = floor_ratio(
                    classification.estimated_net_profit_usd,
                    classification.threshold_usd,
                );
                (0.5..1.0).contains(&ratio)
            })
            .count();
        provisionals += outcome
            .pair_results
            .iter()
            .chain(&outcome.triangle_results)
            .filter(|(_, classification)| {
                matches!(
                    classification.reason,
                    ClassificationReason::Provisional { .. }
                )
            })
            .count();
        if let Some(out) = csv_out.as_mut() {
            // A CSV I/O failure must not kill the whole 24h window: log it
            // once and disable further CSV output, keeping the poller alive.
            let mut write_all = || -> std::io::Result<()> {
                for (_pair, (quote, classification)) in
                    outcome.evaluated.iter().zip(&outcome.pair_results)
                {
                    let lo = quote.token_lo;
                    let hi = quote.token_hi;
                    writeln!(
                        out,
                        "pair,{lo},{hi},{latest},{input},{output},{profit},{log2_skew:.6},{gross},{net},{shortfall},{threshold},{floor:.4},{unclamped},{capacity},{reason_code},{reason_detail},{priced}",
                        lo = lo,
                        hi = hi,
                        latest = latest,
                        input = quote.input,
                        output = quote.output,
                        profit = quote.profit,
                        log2_skew = quote.log2_skew,
                        gross = classification.gross_profit_usd,
                        net = classification.estimated_net_profit_usd,
                        shortfall = classification.shortfall_usd,
                        threshold = classification.threshold_usd,
                        floor = floor_ratio(
                            classification.estimated_net_profit_usd,
                            classification.threshold_usd
                        ),
                        // Audit-S1 single-tick capacity clamp: what the model
                        // wanted vs. what one tick-spacing cell absorbs.
                        unclamped = quote.optimal_unclamped,
                        capacity = quote.input_capacity,
                        reason_code = code_and_detail(&classification.reason).0,
                        reason_detail = code_and_detail(&classification.reason).1,
                        priced = evaluator.token_is_priced(lo),
                    )?;
                }
                for (tri, (quote, classification)) in outcome
                    .triangle_evaluated
                    .iter()
                    .zip(&outcome.triangle_results)
                {
                    let t = evaluator.triangle(*tri);
                    let lo = alloy_primitives::Address::from_slice(&t.0);
                    let hi = alloy_primitives::Address::from_slice(&t.1);
                    writeln!(
                        out,
                        "triangle,{lo},{hi},{latest},{input},{output},{profit},{log2_skew:.6},{gross},{net},{shortfall},{threshold},{floor:.4},{unclamped},{capacity},{reason_code},{reason_detail},{priced}",
                        lo = lo,
                        hi = hi,
                        latest = latest,
                        input = quote.input,
                        output = quote.output,
                        profit = quote.profit,
                        log2_skew = quote.log2_skew,
                        gross = classification.gross_profit_usd,
                        net = classification.estimated_net_profit_usd,
                        shortfall = classification.shortfall_usd,
                        threshold = classification.threshold_usd,
                        floor = floor_ratio(
                            classification.estimated_net_profit_usd,
                            classification.threshold_usd
                        ),
                        unclamped = quote.optimal_unclamped,
                        capacity = quote.input_capacity,
                        reason_code = code_and_detail(&classification.reason).0,
                        reason_detail = code_and_detail(&classification.reason).1,
                        priced = evaluator.token_is_priced(lo),
                    )?;
                }
                Ok(())
            };
            if let Err(error) = write_all() {
                eprintln!("run-pairs: CSV output disabled after write error: {error}");
                csv_out = None;
            } else if let Some(out) = csv_out.as_mut() {
                // Audit A14: BufWriter's Drop ignores flush errors, so an
                // unchecked final flush silently ate the tail of a 24h run.
                // Flush explicitly every poll and propagate the error.
                if let Err(error) = out.flush() {
                    eprintln!("run-pairs: CSV flush failed; output disabled: {error}");
                    csv_out = None;
                }
            }
        }
        last_window = to_eff;
        println!(
            "run-pairs: poll tip={latest} swept_to={to_eff} priced a={} b={} evals={} gated={} triangles={}/{} stale_screened={} dirty={}",
            priced_a.len(),
            priced_b.len(),
            outcome.evaluated.len(),
            outcome.interesting.len(),
            outcome.triangle_interesting.len(),
            outcome.triangle_evaluated.len(),
            outcome.stale_screened.len() + outcome.triangle_stale_screened.len(),
            outcome.not_evaluated.len(),
        );
        std::thread::sleep(poll);
    }

    let dirty_now = evaluator.queue_len();
    println!(
        "run-pairs: done at block {} applied={} evals={} gated={} triangles={}/{} stale_screened={} near_miss={} provisional={} not_evaluated={} dirty={} elapsed_s={}",
        last_window,
        applied,
        evals,
        interesting,
        triangle_interesting,
        triangle_evals,
        stale_screened,
        near_misses,
        provisionals,
        not_evaluated,
        dirty_now,
        since.elapsed().as_secs(),
    );
    Ok(())
}

/// Machine-readable classification code plus its free-form detail, emitted as
/// a pre-quoted CSV field (audit A18): `{:?}` of an enum payload embedded
/// braces, spaces and arbitrary strings unquoted — one comma away from
/// breaking every downstream parser retroactively across a whole canary.
fn code_and_detail(reason: &shadow::ClassificationReason) -> (String, String) {
    let (code, detail) = match reason {
        shadow::ClassificationReason::AboveThreshold => ("above_threshold", String::new()),
        shadow::ClassificationReason::BelowThreshold => ("below_threshold", String::new()),
        shadow::ClassificationReason::NotProfitable => ("not_profitable", String::new()),
        shadow::ClassificationReason::NotEvaluated { detail } => ("not_evaluated", detail.clone()),
        shadow::ClassificationReason::Provisional { detail } => ("provisional", detail.clone()),
    };
    // RFC 4180 quoting: wrap in quotes, double embedded quotes.
    let quoted = format!("\"{}\"", detail.replace('"', "\"\""));
    (code.to_owned(), quoted)
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
    deduper: ws_probe::LogDeduper,
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

    /// Connects if needed, drains one bounded item, and returns the log
    /// identity `(block, transaction_index, log_index)` when a new unique
    /// event was counted.
    fn poll(
        &mut self,
        ws_url: &RedactedUrl,
        stream: &LogStream,
        timeout: Duration,
        tip: u64,
    ) -> Option<(u64, u64, u64)> {
        self.ensure_connected(ws_url);
        let client = self.client.as_ref()?;
        match client.next(stream, timeout) {
            Ok(Some(StreamItem::Log(envelope))) => {
                if self.deduper.is_duplicate(&envelope) {
                    self.stats.duplicates += 1;
                    return None;
                }
                // Signed: negative means WS delivery is ahead of our HTTP
                // tip view (separate endpoints, separate views).
                let lag = i64::try_from(tip)
                    .ok()
                    .map(|tip| tip - i64::try_from(envelope.block_number).unwrap_or(i64::MAX));
                if let Some(lag) = lag {
                    self.stats.observe_lag(lag);
                }
                Some((
                    envelope.block_number,
                    envelope.transaction_index,
                    envelope.log_index,
                ))
            }
            Ok(Some(StreamItem::Disconnected(_))) | Err(_) => {
                self.schedule_reconnect();
                None
            }
            Ok(None) => None,
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
    // Audit task 4.11 endpoint split: public RHC is the documented default;
    // Alchemy is the opt-in override for archive-heavy work.
    let ws_endpoint = resolve_env_url("ROBINHOOD_WS_RPC_URL", "ALCHEMY_RHC_WS_URL")?;
    let http_endpoint = resolve_env_url("ROBINHOOD_HTTP_RPC_URL", "ALCHEMY_RHC_HTTP_URL")?;
    let ws_url = ws_endpoint
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let http_url = http_endpoint
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    Ok((ws_url, http_url))
}

fn open_raw_csv(path: &std::path::Path) -> Result<std::io::BufWriter<std::fs::File>, String> {
    use std::io::Write;
    let mut writer =
        std::io::BufWriter::new(std::fs::File::create(path).map_err(|error| error.to_string())?);
    writeln!(
        writer,
        "recv_unix_ms,block_number,transaction_index,log_index"
    )
    .map_err(|error| error.to_string())?;
    Ok(writer)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
        })
}

/// HTTP getLogs sidecar for the latency harness: polls the given filters and
/// records each block's first visibility under `source`. Runs until either
/// stop flag is raised.
#[allow(clippy::too_many_arguments)]
fn spawn_http_sidecar(
    http_url: RedactedUrl,
    budget: ProviderBudget,
    filters: Vec<SubscriptionFilter>,
    interval: Duration,
    stop: Arc<AtomicBool>,
    sidecar_stop: Arc<AtomicBool>,
    log: std::sync::Arc<ws_probe::BlockLatencyLog>,
    source: ws_probe::Source,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ab-http".to_owned())
        .spawn(move || {
            let retry = RetryPolicy {
                max_retries: 3,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            };
            let reader = ChainReader::new(
                LiveHttp::new(http_url),
                ThreadSleeper,
                budget,
                retry,
                domain::ROBINHOOD_CHAIN_ID,
            );
            let Ok(mut high_water) = reader.current_block() else {
                return;
            };
            loop {
                if stop.load(std::sync::atomic::Ordering::Relaxed)
                    || sidecar_stop.load(std::sync::atomic::Ordering::Relaxed)
                {
                    return;
                }
                std::thread::sleep(interval);
                let Ok(latest) = reader.current_block() else {
                    continue;
                };
                if latest <= high_water {
                    continue;
                }
                for filter in &filters {
                    let logs = reader.get_logs_windowed(
                        &provider::LogFilter {
                            from_block: high_water + 1,
                            to_block: latest,
                            addresses: filter.addresses.clone(),
                            topic0: filter.topic0,
                            topic0_alternates: Vec::new(),
                        },
                        2_000,
                    );
                    if let Ok(logs) = logs {
                        let seen_ms = now_unix_ms();
                        for raw in &logs {
                            if let Ok(envelope) = provider::RawLogEnvelope::from_rpc_value(raw) {
                                log.observe(source, envelope.block_number, seen_ms);
                            }
                        }
                    }
                }
                high_water = latest;
            }
        })
        .expect("failed to spawn A/B HTTP sidecar thread")
}

/// Writes the per-block comparison CSV (when requested) and prints signed
/// delta summaries: WS-vs-HTTP when a sidecar ran, and Bench-vs-HTTP when a
/// bench endpoint ran.
fn finish_ab_latency(
    ab_log: &std::sync::Arc<ws_probe::BlockLatencyLog>,
    ab_csv: Option<&std::path::Path>,
    has_bench: bool,
) -> Result<(), String> {
    use std::io::Write;
    let rows = ab_log.snapshot_rows();
    if let Some(path) = ab_csv {
        let mut writer =
            std::io::BufWriter::new(std::fs::File::create(path).map_err(|e| e.to_string())?);
        writeln!(
            writer,
            "block_number,ws_first_unix_ms,http_first_unix_ms,bench_first_unix_ms,delta_http_ws_ms,delta_bench_http_ms"
        )
        .map_err(|e| e.to_string())?;
        for (block, ws, http, bench) in &rows {
            let delta = |a: Option<u64>, b: Option<u64>| match (a, b) {
                (Some(x), Some(y)) => (y.cast_signed() - x.cast_signed()).to_string(),
                _ => "-".to_owned(),
            };
            writeln!(
                writer,
                "{block},{},{},{},{},{}",
                ws.map_or("-".to_owned(), |v| v.to_string()),
                http.map_or("-".to_owned(), |v| v.to_string()),
                bench.map_or("-".to_owned(), |v| v.to_string()),
                delta(*ws, *http),
                delta(*http, *bench),
            )
            .map_err(|e| e.to_string())?;
        }
        writer.flush().map_err(|e| e.to_string())?;
    }
    let mut http_ws: Vec<i64> = rows
        .iter()
        .filter_map(|(_, ws, http, _)| match (*ws, *http) {
            (Some(w), Some(h)) => Some(h.cast_signed() - w.cast_signed()),
            _ => None,
        })
        .collect();
    if let Some(summary) = ws_probe::summarize_ab(&mut http_ws) {
        println!(
            "ws-probe: ab-latency blocks={} delta_ms(http-ws) p25={:+} median={:+} p75={:+}",
            summary.blocks, summary.p25_ms, summary.median_ms, summary.p75_ms
        );
    } else if !has_bench {
        println!("ws-probe: ab-latency no blocks observed by both transports");
    }
    if has_bench {
        let mut bench_http: Vec<i64> = rows
            .iter()
            .filter_map(|(_, _, http, bench)| match (*http, *bench) {
                (Some(h), Some(b)) => Some(b.cast_signed() - h.cast_signed()),
                _ => None,
            })
            .collect();
        match ws_probe::summarize_ab(&mut bench_http) {
            Some(summary) => println!(
                "ws-probe: bench-latency blocks={} delta_ms(bench-http) p25={:+} median={:+} p75={:+}",
                summary.blocks, summary.p25_ms, summary.median_ms, summary.p75_ms
            ),
            None => println!("ws-probe: bench-latency no blocks observed by both endpoints"),
        }
    }
    Ok(())
}

/// Optional probe outputs: raw per-event capture and the A/B harness config.
#[derive(Debug, Clone, Copy, Default)]
struct ProbeOutputs<'a> {
    raw_csv: Option<&'a std::path::Path>,
    ab_http_ms: u64,
    ab_csv: Option<&'a std::path::Path>,
    bench_url: Option<&'a str>,
    bench_http_ms: u64,
}

#[allow(clippy::too_many_lines)]
fn run_ws_probe_command(
    manifest_path: &std::path::Path,
    duration_secs: u64,
    limit: u64,
    tip_interval_ms: u64,
    request_cu: u64,
    ws_bytes: u64,
    outputs: ProbeOutputs<'_>,
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
        LiveHttp::new(http_url.clone()),
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
        .clone()
        .into_iter()
        .map(|subscription| WsProbeSlot {
            subscription,
            client: None,
            stats: ws_probe::ProbeStats::default(),
            deduper: ws_probe::LogDeduper::new(),
            attempts: 0,
            retry_at: None,
        })
        .collect();
    let mut total_events = 0u64;
    let mut raw_csv = outputs.raw_csv.map(open_raw_csv).transpose()?;
    let ab_log = std::sync::Arc::new(ws_probe::BlockLatencyLog::new());
    let mut sidecar_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut sidecar_stops: Vec<std::sync::Arc<AtomicBool>> = Vec::new();
    if outputs.ab_http_ms > 0 {
        let sidecar_stop = Arc::new(AtomicBool::new(false));
        sidecar_handles.push(spawn_http_sidecar(
            http_url.clone(),
            budget.clone(),
            subscriptions.iter().map(|s| s.filter.clone()).collect(),
            Duration::from_millis(outputs.ab_http_ms.max(200)),
            std::sync::Arc::clone(&stop.flag),
            std::sync::Arc::clone(&sidecar_stop),
            std::sync::Arc::clone(&ab_log),
            ws_probe::Source::Http,
        ));
        sidecar_stops.push(sidecar_stop);
        println!(
            "ws-probe: A/B HTTP sidecar polling every {}ms",
            outputs.ab_http_ms
        );
    }
    if outputs.bench_http_ms > 0 {
        let bench_endpoint = outputs.bench_url.map_or_else(
            || {
                std::env::var("ROBINHOOD_HTTP_RPC_URL")
                    .map_err(|_| "missing ROBINHOOD_HTTP_RPC_URL (bench fallback)".to_owned())
            },
            |value| {
                value.strip_prefix("env:").map_or_else(
                    || Ok(value.to_owned()),
                    |var| std::env::var(var).map_err(|_| format!("missing {var}")),
                )
            },
        )?;
        let bench_url: RedactedUrl = bench_endpoint
            .parse::<RedactedUrl>()
            .map_err(|error| error.to_string())?;
        let bench_sidecar_stop = Arc::new(AtomicBool::new(false));
        sidecar_handles.push(spawn_http_sidecar(
            bench_url.clone(),
            budget.clone(),
            subscriptions.iter().map(|s| s.filter.clone()).collect(),
            Duration::from_millis(outputs.bench_http_ms.max(200)),
            std::sync::Arc::clone(&stop.flag),
            std::sync::Arc::clone(&bench_sidecar_stop),
            std::sync::Arc::clone(&ab_log),
            ws_probe::Source::Bench,
        ));
        sidecar_stops.push(bench_sidecar_stop);
        println!(
            "ws-probe: bench HTTP sidecar ({}) polling every {}ms",
            bench_url, outputs.bench_http_ms
        );
    }
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
            if let Some((block, tx_index, log_index)) = slot.poll(&ws_url, &stream, poll_slice, tip)
            {
                total_events += 1;
                let recv_ms = now_unix_ms();
                ab_log.observe(ws_probe::Source::Ws, block, recv_ms);
                if let Some(writer) = raw_csv.as_mut() {
                    use std::io::Write;
                    let _ = writeln!(writer, "{recv_ms},{block},{tx_index},{log_index}");
                }
            }
        }
        if Instant::now() >= next_progress {
            print_probe_progress(&slots, started, budget.snapshot(), tip);
            next_progress += Duration::from_secs(10);
        }
    }

    let window = merged_probe_stats(&slots);
    let has_bench = outputs.bench_http_ms > 0;
    for stop_flag in &sidecar_stops {
        stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    for handle in sidecar_handles {
        handle.join().map_err(|_| "sidecar panicked".to_owned())?;
    }
    finish_ab_latency(&ab_log, outputs.ab_csv, has_bench)?;
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

fn print_probe_progress(
    slots: &[WsProbeSlot],
    started: Instant,
    usage: provider::UsageSnapshot,
    tip: u64,
) {
    let parts: Vec<String> = slots
        .iter()
        .map(|slot| {
            format!(
                "{}:events={}+dupes={}+r{}+maxlag{}",
                slot.subscription.label,
                slot.stats.events,
                slot.stats.duplicates,
                slot.stats.reconnects,
                slot.stats.lag_max_blocks()
            )
        })
        .collect();
    println!(
        "{} [{}]",
        ws_probe::progress_line(
            started.elapsed().as_secs(),
            &merged_probe_stats(slots),
            usage.websocket_delivered_bytes,
            tip,
        ),
        parts.join(" ")
    );
}

fn print_probe_summary(
    elapsed_secs: u64,
    window: &ws_probe::ProbeStats,
    reason: &str,
    budget: &ProviderBudget,
) {
    println!(
        "ws-probe: done elapsed_s={} events={} dupes={} lag_blocks min/mean/max={}/{:.1}/{} reconnects={} reason={}",
        elapsed_secs,
        window.events,
        window.duplicates,
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
    // Audit A15: the disabled gate is now a *named* decision in
    // shadow::gate_defaults — `interesting=` counts every profitable cycle
    // because gas is dust and the win rate is 100%.
    let economics = Economics {
        flash_fee_rate: U256::ZERO,
        gas_cost_usd: shadow::gate_defaults::MEASUREMENT_GAS_COST_WEI,
        expected_win_rate: shadow::gate_defaults::MEASUREMENT_EXPECTED_WIN_RATE,
        native_token_usd: U256::from(FIXED_POINT_SCALE),
        da_fee_usd: U256::ZERO,
    };
    let reference = CostSnapshot {
        usd_per_token: U256::from(FIXED_POINT_SCALE),
        gas_price_age_valid: true,
        reference_price_valid: true,
        gas_price_wei: U256::ZERO,
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
