//! Read-only pool lens: token address → every known pool → live board.
//!
//! Answers "where does this token trade, at what price, with what depth"
//! from live chain state, so manual opportunity checks never again rely on
//! truncated addresses, guessed token labels, or stale index prices. All
//! reads go through the [`ChainReader`]; nothing here signs or broadcasts.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::{Address, U256};
use provider::{
    ChainReader, LiveHttp, LogFilter, ProviderBudget, RedactedUrl, RetryPolicy, ThreadSleeper,
};

use crate::gaps::{self, PoolEntry};
use domain::ROBINHOOD_CHAIN_ID;

/// Arguments for the `pool-lens` command (boxed at the call site to keep
/// the `Command` enum small).
#[derive(Debug, clap::Args)]
pub struct PoolLensArgs {
    /// Token contract address to inspect.
    #[arg(long)]
    pub token: String,
    /// RPC endpoint (URL or `env:VAR_NAME`); defaults to the
    /// Chainstack-first env chain, then the public RHC gateway.
    #[arg(long)]
    pub rpc: Option<String>,
    /// `PoolManager` address for V4 reads (defaults to the RHC singleton).
    #[arg(long)]
    pub pool_manager: Option<String>,
    /// Catalog CSVs to scan for pools containing the token (repeatable).
    #[arg(long)]
    pub catalog: Vec<PathBuf>,
    /// Extra V3 pool addresses to inspect (repeatable; covers pools absent
    /// from every catalog — token0/token1 read live).
    #[arg(long)]
    pub v3: Vec<String>,
    /// Extra V4 pool IDs (66-char hex) to inspect (repeatable; needs a
    /// catalog row for pair/fee context, else reported unpriced).
    #[arg(long)]
    pub v4: Vec<String>,
    /// Counterparty USD prices as `0xaddr:1.23` (repeatable; `DexScreener`
    /// values are indicative — flagged as such in the output).
    #[arg(long)]
    pub price: Vec<String>,
    /// Native (ETH/WETH) USD price for depth math.
    #[arg(long, default_value = "2490")]
    pub native_usd: String,
    /// Quote size in USD for the impact estimate.
    #[arg(long, default_value_t = 500.0)]
    pub size_usd: f64,
    /// Minimum counterparty-side depth in USD for spread-matrix legs
    /// (filters dust pools whose ratios are real but unfillable).
    #[arg(long, default_value_t = 100.0)]
    pub min_depth_usd: f64,
    /// Recent-swap activity window in blocks.
    #[arg(long, default_value_t = 40)]
    pub activity_window: u64,
    /// V4 state source: `extsload` (raw mapping reads, default) or
    /// `stateview` (canonical lens).
    #[arg(long, default_value = "extsload")]
    pub reads: String,
    /// Read both sources per V4 pool and annotate agreement in the row
    /// note (read-only; for the Phase-1 cross-check, no pricing change).
    #[arg(long, default_value_t = false)]
    pub cross_check_reads: bool,
    /// Verify each priced V4 leg against the on-chain `V4Quoter`
    /// (read-only `eth_call`s): prints `quoter:` comparison lines of
    /// math-model output vs executable output at capacity fractions.
    /// Needs `--overrides` for exact PoolKey fields. Default off.
    #[arg(long, default_value_t = false)]
    pub quoter: bool,
    /// V4 overrides CSV (`pool_id,tick_spacing,hooks`) for exact quoter
    /// PoolKeys. Required with `--quoter`.
    #[arg(long)]
    pub overrides: Option<PathBuf>,
}

/// One inspected pool row on the live board.
#[derive(Debug, Clone)]
pub struct LensRow {
    pub label: String,
    pub profile: [u8; 2],
    pub token0: Address,
    pub token1: Address,
    /// False when the pair came from a bare --v4 id with no catalog row
    /// (USD math skipped rather than guessed).
    pub pair_known: bool,
    pub fee_bps: Option<u64>,
    pub dynamic_fee: bool,
    pub sqrt: Option<U256>,
    pub liquidity: Option<U256>,
    /// Token1-per-token0 price (None when undecodable).
    pub price_ratio: Option<f64>,
    /// Token USD price via the counterparty leg (None when unpriced).
    pub token_usd: Option<f64>,
    /// Counterparty-side virtual reserve in USD (None when unpriced).
    pub depth_usd: Option<f64>,
    /// Token-side virtual reserve in USD (None when unpriced). Both sides
    /// must clear `--min-depth-usd` for a matrix leg: buying needs token
    /// depth, selling needs counterparty depth.
    pub token_depth_usd: Option<f64>,
    pub swaps_in_window: Option<u64>,
    pub note: Option<String>,
}

/// Adaptive USD formatting: full precision for dust, 6dp otherwise.
fn fmt_usd(value: f64) -> String {
    if value > 0.0 && value < 0.0001 {
        format!("${value:.2e}")
    } else {
        format!("${value:.6}")
    }
}
/// Relative spread `buy_price` -> `sell_price` as a fraction (0.044 = 4.4%).
#[must_use]
pub fn spread_fraction(buy_price: f64, sell_price: f64) -> f64 {
    if buy_price <= 0.0 {
        return 0.0;
    }
    sell_price / buy_price - 1.0
}

fn u256_to_f64(value: U256) -> f64 {
    let bytes = value.to_be_bytes::<32>();
    let mut acc = 0.0f64;
    for byte in bytes {
        acc = acc * 256.0 + f64::from(byte);
    }
    acc
}

fn parse_price(spec: &str) -> Result<(Address, f64), String> {
    let (addr, price) = spec
        .split_once(':')
        .ok_or_else(|| format!("--price expects 0xaddr:usd, got {spec:?}"))?;
    let address =
        Address::from_str(addr).map_err(|_| format!("invalid --price address {addr:?}"))?;
    let usd: f64 = price
        .parse()
        .map_err(|_| format!("invalid --price value {price:?}"))?;
    if !usd.is_finite() || usd < 0.0 {
        return Err(format!("invalid --price value {price:?}"));
    }
    Ok((address, usd))
}

fn parse_hex_id(spec: &str) -> Result<[u8; 32], String> {
    let hex = spec.strip_prefix("0x").unwrap_or(spec);
    if hex.len() != 64 {
        return Err(format!("--v4 expects 66-char hex, got {spec:?}"));
    }
    let mut id = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| format!("bad hex {spec:?}"))?;
        id[i] = u8::from_str_radix(s, 16).map_err(|_| format!("bad hex {spec:?}"))?;
    }
    Ok(id)
}

fn entry_key(entry: &PoolEntry) -> [u8; 32] {
    gaps::pool_key(entry)
}

type Reader = ChainReader<LiveHttp, ThreadSleeper>;

fn read_decimals(reader: &Reader, token: Address, tip: u64) -> u32 {
    reader
        .call(
            token,
            &alloy_primitives::Bytes::from(vec![0x31, 0x3c, 0xe5, 0x67]),
            tip,
        )
        .ok()
        .and_then(|raw| raw.last().copied())
        .map_or(18, u32::from)
}

/// One candidate pool to inspect (dedupe key + live-read context).
struct Candidate {
    label: String,
    profile: [u8; 2],
    key: [u8; 32],
    venue: Address,
    id: Option<[u8; 32]>,
    fee: Option<u64>,
    /// Raw catalog fee (V4 u24 incl. sentinels): the exact PoolKey fee for
    /// quoter calls. Normalized `fee` above cannot reconstruct it.
    fee_raw: Option<u32>,
    token0: Option<Address>,
    token1: Option<Address>,
}

/// Live context shared across the lens stages.
struct LensCtx {
    reader: Reader,
    tip: u64,
    pm: Address,
    state_view: Address,
    v4_reads: gaps::V4Reads,
    cross_check_reads: bool,
    /// Quoter verification (Phase 2): exact PoolKey components per pool.
    quoter: bool,
    quoter_addr: Address,
    overrides: HashMap<String, (i32, Address)>,
    token: Address,
    token_decimals: u32,
    native_usd: f64,
    usd: HashMap<Address, (f64, &'static str)>,
    decimals: HashMap<Address, u32>,
    activity_window: u64,
}

impl LensCtx {
    fn decimals(&mut self, token: Address) -> u32 {
        if let Some(decimals) = self.decimals.get(&token) {
            return *decimals;
        }
        let tip = self.tip;
        let decimals = read_decimals(&self.reader, token, tip);
        self.decimals.insert(token, decimals);
        decimals
    }
}

/// Resolves arguments into a live context: endpoint, reader, chain gate,
/// tip, token meta, and counterparty USD map.
fn resolve_lens(args: &PoolLensArgs) -> Result<LensCtx, String> {
    let token =
        Address::from_str(&args.token).map_err(|_| format!("invalid --token {:?}", args.token))?;
    let pm = match &args.pool_manager {
        Some(value) => {
            Address::from_str(value).map_err(|_| format!("invalid --pool-manager {value:?}"))?
        }
        None => super::V4_POOL_MANAGER,
    };
    let v4_reads = match args.reads.as_str() {
        "extsload" => gaps::V4Reads::Extsload,
        "stateview" => gaps::V4Reads::StateView,
        other => {
            return Err(format!(
                "unknown --reads {other:?} (expected extsload or stateview)"
            ));
        }
    };
    let endpoint = match &args.rpc {
        Some(value) => value.strip_prefix("env:").map_or_else(
            || Ok(value.to_owned()),
            |var| std::env::var(var).map_err(|_| format!("missing {var}")),
        )?,
        None => super::resolve_env_url_chain(&[
            "CHAINSTACK_RHC_HTTP_URL",
            "ROBINHOOD_HTTP_RPC_URL",
            "ALCHEMY_RHC_HTTP_URL",
        ])
        .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned()),
    };
    let http_url: RedactedUrl = endpoint
        .parse::<RedactedUrl>()
        .map_err(|error| error.to_string())?;
    let reader = ChainReader::new(
        LiveHttp::new(http_url),
        ThreadSleeper,
        ProviderBudget::new(1_000_000, 1 << 24),
        RetryPolicy {
            max_retries: 3,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(2),
        },
        ROBINHOOD_CHAIN_ID,
    );
    reader
        .validate_chain_id()
        .map_err(|error| error.to_string())?;
    let tip = reader.current_block().map_err(|error| error.to_string())?;
    // Token meta (best-effort; never fatal).
    let code_len = reader.code(token, tip).map_or(0, |code| code.len());
    let mut ctx = LensCtx {
        reader,
        tip,
        pm,
        state_view: super::RHC_STATE_VIEW,
        v4_reads,
        cross_check_reads: args.cross_check_reads,
        quoter: args.quoter,
        quoter_addr: super::RHC_V4_QUOTER,
        overrides: if args.quoter {
            let path = args
                .overrides
                .as_ref()
                .ok_or("--quoter needs --overrides (exact PoolKey tickSpacing/hooks)")?;
            crate::submit::trade::load_overrides(path)?
        } else {
            HashMap::new()
        },
        token,
        token_decimals: 18,
        native_usd: args
            .native_usd
            .parse()
            .map_err(|_| format!("invalid --native-usd {:?}", args.native_usd))?,
        usd: HashMap::new(),
        decimals: HashMap::new(),
        activity_window: args.activity_window,
    };
    ctx.token_decimals = ctx.decimals(token);
    println!(
        "pool-lens: token 0x{} code={code_len}B decimals={} tip={tip}",
        alloy_primitives::hex::encode(token),
        ctx.token_decimals,
    );
    // Counterparty USD map: native + explicit --price entries (indicative).
    for spec in &args.price {
        let (addr, price) = parse_price(spec)?;
        ctx.usd.insert(addr, (price, "indicative"));
    }
    Ok(ctx)
}

/// Runs the lens: prints a token summary, a live pool board, a spread
/// matrix over USD-priced legs, and a depth-aware verdict.
///
/// # Errors
///
/// Returns a message when arguments are invalid or reads fail.
pub fn run_pool_lens(args: &PoolLensArgs) -> Result<(), String> {
    let mut ctx = resolve_lens(args)?;
    let pools = collect_candidates(args, &ctx)?;
    if pools.is_empty() {
        return Err("no pools found for token (catalogs empty and no --v3/--v4 given)".to_owned());
    }
    let (v4_activity, v3_activity) = snapshot_activity(&ctx);
    let rows = build_rows(&mut ctx, &pools, &v4_activity, &v3_activity);
    print_board(&rows, args.activity_window);
    print_spreads(&rows, args);
    if ctx.quoter {
        verify_quoter(&ctx, &pools, &rows);
    }
    Ok(())
}

/// Phase-2 quoter verification (read-only): for every priced zero-hook V4
/// row with an exact static fee, quotes both directions at 10/50/100% of
/// single-tick capacity through the on-chain `V4Quoter` and prints
/// `quoter:` comparison lines (math vs executable). Skips dynamic-fee,
/// unknown-fee, hook, and over-u128 rows with counted reasons — never
/// guesses a PoolKey.
#[allow(clippy::too_many_lines)]
fn verify_quoter(ctx: &LensCtx, pools: &[Candidate], rows: &[LensRow]) {
    // (label, numerator, denominator): exact integer sizing, no float input.
    const FRACTIONS: [(&str, u64, u64); 3] = [("0.1", 1, 10), ("0.5", 1, 2), ("1.0", 1, 1)];
    let mut quoted = 0u64;
    let mut skipped_fee = 0u64;
    let mut skipped_hooks = 0u64;
    let mut skipped_size = 0u64;
    let mut skipped_state = 0u64;
    let mut errored = 0u64;
    // Chainstack free archive-gates `eth_call` at stale block numbers, so
    // re-pin the tip every 20 pools; a minutes-old pinned tip 403s (-32002)
    // and would masquerade as quoter failure. (Prod quoter calls in Phase 4
    // must likewise use the latest poll block, never a pinned tip.)
    let mut tip = ctx.tip;
    let mut since_repin = 0u64;
    for (candidate, row) in pools.iter().zip(rows.iter()) {
        if candidate.profile != *b"v4" || !row.pair_known {
            continue;
        }
        let Some(pool_id) = candidate.id else {
            continue;
        };
        let (Some(sqrt), Some(liquidity)) = (row.sqrt, row.liquidity) else {
            skipped_state += 1;
            continue;
        };
        // Exact PoolKey only: static raw fee + overrides tickSpacing/hooks.
        let fee_raw = match candidate.fee_raw {
            Some(f) if f != 0 && f & gaps::V4_DYNAMIC_FEE_FLAG == 0 => f,
            _ => {
                skipped_fee += 1;
                continue;
            }
        };
        let id_hex = alloy_primitives::hex::encode(pool_id);
        if since_repin >= 20 {
            tip = ctx.reader.current_block().unwrap_or(tip);
            since_repin = 0;
        }
        since_repin += 1;
        let Some((tick_spacing, hooks)) = ctx.overrides.get(&id_hex) else {
            skipped_fee += 1;
            continue;
        };
        if *hooks != Address::ZERO {
            skipped_hooks += 1;
            continue;
        }
        let (c0, c1) = if row.token0.as_slice() < row.token1.as_slice() {
            (row.token0, row.token1)
        } else {
            (row.token1, row.token0)
        };
        let (r0, r1) = gaps::virtual_reserves(sqrt, liquidity);
        let (r0f, r1f) = (gaps::f64_of(r0), gaps::f64_of(r1));
        let toll = f64::from(fee_raw) / 1_000_000.0;
        for zero_for_one in [true, false] {
            let cap = gaps::single_tick_capacity(sqrt, liquidity, *tick_spacing, zero_for_one);
            if cap.is_zero() {
                skipped_size += 1;
                continue;
            }
            let (rin_f, rout_f) = if zero_for_one { (r0f, r1f) } else { (r1f, r0f) };
            for (label, num, den) in FRACTIONS {
                let dx = cap * U256::from(num) / U256::from(den.max(1));
                if dx.is_zero() {
                    skipped_size += 1;
                    continue;
                }
                let Ok(dx_u128) = u128::try_from(dx) else {
                    skipped_size += 1;
                    continue;
                };
                let Some(math_out) = gaps::cp_output(rin_f, rout_f, gaps::f64_of(dx), toll) else {
                    skipped_size += 1;
                    continue;
                };
                match ctx.reader.quote_v4_exact_input(
                    ctx.quoter_addr,
                    c0,
                    c1,
                    fee_raw,
                    *tick_spacing,
                    *hooks,
                    zero_for_one,
                    dx_u128,
                    tip,
                ) {
                    Ok((quoter_out, gas_est)) => {
                        let qf = gaps::f64_of(quoter_out);
                        let div = if math_out > 0.0 {
                            1.0 - qf / math_out
                        } else {
                            f64::NAN
                        };
                        quoted += 1;
                        println!(
                            "quoter pool=0x{} dir={} frac={} cap_in={} math_out={:.0} quoter_out={} div={:.4} gas_est={}",
                            &id_hex[..10],
                            if zero_for_one { "zfo" } else { "ofz" },
                            label,
                            dx_u128,
                            math_out,
                            quoter_out,
                            div,
                            gas_est,
                        );
                    }
                    Err(error) => {
                        // Diagnostic surface: a revert here usually means the
                        // manifest fee is stale (wrong PoolKey → uninitialized
                        // pool) — one capped line per pool, not silence.
                        let detail = format!("{error:?}");
                        let short: String = detail.chars().take(120).collect();
                        eprintln!("quoter pool=0x{} error: {short}", &id_hex[..10]);
                        errored += 1;
                    }
                }
            }
        }
    }
    println!(
        "quoter: quoted={quoted} skipped_fee={skipped_fee} skipped_hooks={skipped_hooks} skipped_size={skipped_size} skipped_state={skipped_state} errored={errored}"
    );
}

/// Collects candidate pools from catalogs plus explicit `--v3`/`--v4`
/// lists (deduped by profile+key). Catalog fees normalize to basis points;
/// explicit lists carry no fee/pair context until live reads fill it in.
///
/// # Errors
///
/// Returns a message for unreadable catalogs or malformed addresses/ids.
fn collect_candidates(args: &PoolLensArgs, ctx: &LensCtx) -> Result<Vec<Candidate>, String> {
    let token = ctx.token;
    let pm = ctx.pm;
    let reader = &ctx.reader;
    let tip = ctx.tip;
    let mut pools: Vec<Candidate> = Vec::new();
    let mut seen: HashSet<([u8; 2], [u8; 32])> = HashSet::new();
    let mut push = |mut candidate: Candidate| {
        if seen.insert((candidate.profile, candidate.key)) {
            // Short venue tag (pool address or pool id prefix) so rows
            // from the same source stay distinguishable.
            let tag = alloy_primitives::hex::encode(&candidate.key[..5]);
            candidate.label = format!("{}:0x{tag}", candidate.label);
            pools.push(candidate);
        }
    };
    for path in &args.catalog {
        let entries = gaps::load_catalog(path, None, None)?;
        for entry in entries.values() {
            if entry.token0 != token && entry.token1 != token {
                continue;
            }
            // Fee normalized to basis points: V3 stores numerator over
            // fee_denominator (usually 1e6); V4 stores hundredths of a bip
            // (1e6 = 100%), with 0 / 0x800000 = hook-set dynamic.
            let fee = if entry.profile == *b"v4"
                && (entry.fee == 0 || entry.fee & gaps::V4_DYNAMIC_FEE_FLAG != 0)
            {
                None
            } else if entry.profile == *b"v4" {
                Some(u64::from(entry.fee) / 100)
            } else if entry.fee_denominator == 0 {
                None
            } else {
                Some(u64::from(entry.fee) * 10_000 / u64::from(entry.fee_denominator))
            };
            push(Candidate {
                label: path.display().to_string(),
                profile: entry.profile,
                key: entry_key(entry),
                venue: entry.venue,
                id: if entry.profile == *b"v4" {
                    Some(entry.id)
                } else {
                    None
                },
                fee,
                fee_raw: if entry.profile == *b"v4" {
                    Some(entry.fee)
                } else {
                    None
                },
                token0: Some(entry.token0),
                token1: Some(entry.token1),
            });
        }
    }
    for addr in &args.v3 {
        let venue =
            Address::from_str(addr).map_err(|_| format!("invalid --v3 address {addr:?}"))?;
        // Token order read live (V3 token0()/token1()).
        let t0 = reader
            .call(
                venue,
                &alloy_primitives::Bytes::from(vec![0x0d, 0xfe, 0x16, 0x81]),
                tip,
            )
            .ok()
            .and_then(|raw| raw.get(12..32)?.try_into().ok())
            .map(Address::from_word);
        let t1 = reader
            .call(
                venue,
                &alloy_primitives::Bytes::from(vec![0xd2, 0x12, 0x20, 0xa7]),
                tip,
            )
            .ok()
            .and_then(|raw| raw.get(12..32)?.try_into().ok())
            .map(Address::from_word);
        let (token0, token1) = match (t0, t1) {
            (Some(t0), Some(t1)) => (Some(t0), Some(t1)),
            _ => (None, None),
        };
        push(Candidate {
            label: "--v3".to_owned(),
            profile: *b"v3",
            key: venue.into_word().into(),
            venue,
            id: None,
            fee: None,
            fee_raw: None,
            token0,
            token1,
        });
    }
    for id_spec in &args.v4 {
        let id = parse_hex_id(id_spec)?;
        push(Candidate {
            label: "--v4".to_owned(),
            profile: *b"v4",
            key: id,
            venue: pm,
            id: Some(id),
            fee: None,
            fee_raw: None,
            token0: None,
            token1: None,
        });
    }
    if pools.is_empty() {
        return Err("no pools found for token (catalogs empty and no --v3/--v4 given)".to_owned());
    }
    Ok(pools)
}

/// Recent-swap activity snapshot: one PM-wide V4 query plus one global V3
/// query over the window, counted per pool (V4 by topic1 pool ID, V3 by
/// pool address). Read failures yield empty maps, never fatal.
fn snapshot_activity(ctx: &LensCtx) -> (HashMap<[u8; 32], u64>, HashMap<Address, u64>) {
    let from = ctx.tip.saturating_sub(ctx.activity_window.max(1));
    let v4_logs = ctx
        .reader
        .get_logs(&LogFilter {
            from_block: from,
            to_block: ctx.tip,
            addresses: vec![ctx.pm],
            topic0: provider::v4_swap_topic(),
            topic0_alternates: Vec::new(),
        })
        .unwrap_or_default();
    let v3_logs = ctx
        .reader
        .get_logs(&LogFilter {
            from_block: from,
            to_block: ctx.tip,
            addresses: Vec::new(),
            topic0: provider::v3_swap_topic(),
            topic0_alternates: Vec::new(),
        })
        .unwrap_or_default();
    let mut v4_activity: HashMap<[u8; 32], u64> = HashMap::new();
    for raw in &v4_logs {
        let Ok(env) = provider::RawLogEnvelope::from_rpc_value(raw) else {
            continue;
        };
        if env.topics.len() >= 2 {
            *v4_activity.entry(env.topics[1].0).or_insert(0) += 1;
        }
    }
    let mut v3_activity: HashMap<Address, u64> = HashMap::new();
    for raw in &v3_logs {
        if let Ok(env) = provider::RawLogEnvelope::from_rpc_value(raw) {
            *v3_activity.entry(env.address).or_insert(0) += 1;
        }
    }
    (v4_activity, v3_activity)
}

/// Reads live state for every candidate and prices the legs whose
/// counterparty has a known USD value (native or explicit `--price`).
fn build_rows(
    ctx: &mut LensCtx,
    pools: &[Candidate],
    v4_activity: &HashMap<[u8; 32], u64>,
    v3_activity: &HashMap<Address, u64>,
) -> Vec<LensRow> {
    let mut rows: Vec<LensRow> = Vec::new();
    for candidate in pools {
        let mut row = LensRow {
            label: candidate.label.clone(),
            profile: candidate.profile,
            token0: candidate.token0.unwrap_or(Address::ZERO),
            token1: candidate.token1.unwrap_or(Address::ZERO),
            pair_known: candidate.token0.is_some() && candidate.token1.is_some(),
            fee_bps: candidate.fee,
            dynamic_fee: candidate.fee.is_none() && candidate.profile == *b"v4",
            sqrt: None,
            liquidity: None,
            price_ratio: None,
            token_usd: None,
            depth_usd: None,
            token_depth_usd: None,
            swaps_in_window: None,
            note: candidate
                .token0
                .is_none_or(|_| candidate.token1.is_none())
                .then(|| "pair unknown (no catalog row); USD needs --catalog".to_owned()),
        };
        read_row_state(ctx, candidate, &mut row, v4_activity, v3_activity);
        price_row(ctx, &mut row);
        rows.push(row);
    }
    rows
}

/// One-line error kind for cross-check notes (first 200 chars while
/// diagnosing Phase-1 agreement; the redacted transport layer never
/// carries credentials).
fn short_err<T: std::fmt::Debug>(result: &Result<T, provider::TransportError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => {
            let full = format!("{error:?}");
            full.chars().take(200).collect()
        }
    }
}

/// Reads live slot/liquidity state for one candidate into its row.
fn read_row_state(
    ctx: &LensCtx,
    candidate: &Candidate,
    row: &mut LensRow,
    v4_activity: &HashMap<[u8; 32], u64>,
    v3_activity: &HashMap<Address, u64>,
) {
    if candidate.profile == *b"v4" {
        let Some(pool_id) = candidate.id else {
            row.note = Some("v4 entry without pool id".to_owned());
            return;
        };
        // Phase 1: selectable read source; cross-check mode reads both and
        // annotates agreement (the acceptance evidence for the cutover).
        let tip = ctx.tip;
        let primary = match ctx.v4_reads {
            gaps::V4Reads::StateView => ctx.reader.pool_v4_state_view(ctx.state_view, pool_id, tip),
            gaps::V4Reads::Extsload => ctx.reader.pool_v4_state(ctx.pm, pool_id),
        };
        let mut source = match ctx.v4_reads {
            gaps::V4Reads::StateView => "stateview",
            gaps::V4Reads::Extsload => "extsload",
        };
        let mut state = primary;
        if state.is_err() {
            // Fail over to the other source before giving up on the row.
            state = match ctx.v4_reads {
                gaps::V4Reads::StateView => ctx.reader.pool_v4_state(ctx.pm, pool_id),
                gaps::V4Reads::Extsload => {
                    ctx.reader.pool_v4_state_view(ctx.state_view, pool_id, tip)
                }
            };
            source = "fallback";
        }
        if ctx.cross_check_reads {
            let other = match ctx.v4_reads {
                gaps::V4Reads::StateView => ctx.reader.pool_v4_state(ctx.pm, pool_id),
                gaps::V4Reads::Extsload => {
                    ctx.reader.pool_v4_state_view(ctx.state_view, pool_id, tip)
                }
            };
            let agree = match (&state, &other) {
                (Ok((s1, l1)), Ok((s2, l2))) => {
                    if s1 == s2 && l1 == l2 {
                        "reads-agree".to_owned()
                    } else {
                        "READS-DIVERGE".to_owned()
                    }
                }
                // Cross-check diagnostics: the failing side's error kind is
                // evidence (rate limit vs decode vs revert), never a secret
                // (provider URL types redact credentials).
                _ => format!(
                    "reads-incomplete primary_err={} other_err={}",
                    short_err(&state),
                    short_err(&other)
                ),
            };
            row.note = Some(format!(
                "{agree} primary={source}{}",
                row.note
                    .as_deref()
                    .map_or(String::new(), |n| format!("; {n}"))
            ));
        }
        match state {
            Ok((sqrt, liquidity)) => {
                row.sqrt = Some(sqrt);
                row.liquidity = Some(liquidity);
                row.swaps_in_window = Some(*v4_activity.get(&pool_id).unwrap_or(&0));
                let f = u256_to_f64(sqrt) / 2f64.powi(96);
                row.price_ratio = Some(f * f);
            }
            Err(error) => {
                // Cross-check mode: both sources failed identically (dead
                // pool) — keep the agreement tag, don't overwrite it.
                let tag = row.note.as_deref().map_or(String::new(), |n| {
                    if n.starts_with("reads-") {
                        format!("{n}; ")
                    } else {
                        String::new()
                    }
                });
                row.note = Some(format!("{tag}uninitialized ({error})"));
            }
        }
        return;
    }
    match ctx.reader.pool_slot0(candidate.venue) {
        Ok((sqrt, _tick)) => {
            row.sqrt = Some(sqrt);
            let f = u256_to_f64(sqrt) / 2f64.powi(96);
            row.price_ratio = Some(f * f);
            match ctx.reader.pool_liquidity(candidate.venue) {
                Ok(liquidity) => row.liquidity = Some(liquidity),
                Err(error) => {
                    row.note = Some(format!("liquidity read failed ({error})"));
                }
            }
            row.swaps_in_window = Some(*v3_activity.get(&candidate.venue).unwrap_or(&0));
        }
        Err(error) => {
            row.note = Some(format!("slot0 reverted ({error})"));
        }
    }
}

/// Prices one row in USD when its counterparty leg is known natively or
/// via `--price`. Unknown pairs are never guessed.
fn price_row(ctx: &mut LensCtx, row: &mut LensRow) {
    let (Some(ratio), Some(sqrt), Some(liquidity)) = (row.price_ratio, row.sqrt, row.liquidity)
    else {
        return;
    };
    let token = ctx.token;
    let counterparty = if !row.pair_known {
        None
    } else if row.token0 == token {
        Some(row.token1)
    } else if row.token1 == token {
        Some(row.token0)
    } else {
        None
    };
    let counterparty_usd = match counterparty {
        Some(addr) if addr != token && is_native(addr) => Some((ctx.native_usd, "native")),
        Some(addr) if addr != token => ctx.usd.get(&addr).copied(),
        _ => None,
    };
    let (Some(counterparty), Some((counter_usd, _source))) = (counterparty, counterparty_usd)
    else {
        return;
    };
    // ratio is token1-per-token0. Token-per-counterparty is ratio when
    // the token is token1, else its reciprocal: 1 WETH = 46,416 BONER
    // means 1 BONER = $2,490/46,416.
    let token_per_counterparty = if row.token1 == token {
        1.0 / ratio
    } else {
        ratio
    };
    if !token_per_counterparty.is_finite() || token_per_counterparty <= 0.0 {
        return;
    }
    row.token_usd = Some(token_per_counterparty * counter_usd);
    let (r0, r1) = gaps::virtual_reserves(sqrt, liquidity);
    let counter_reserve = if row.token1 == token { r0 } else { r1 };
    let token_reserve = if row.token1 == token { r1 } else { r0 };
    let counter_decimals = ctx.decimals(counterparty);
    let scale = 10f64.powi(i32::try_from(counter_decimals).unwrap_or(18));
    row.depth_usd = Some(u256_to_f64(counter_reserve) / scale * counter_usd);
    let token_scale = 10f64.powi(i32::try_from(ctx.token_decimals).unwrap_or(18));
    row.token_depth_usd =
        Some(u256_to_f64(token_reserve) / token_scale * token_per_counterparty * counter_usd);
}

/// Prints the live board, one line per pool.
fn print_board(rows: &[LensRow], activity_window: u64) {
    for row in rows {
        let prof = String::from_utf8_lossy(&row.profile);
        let px = row
            .price_ratio
            .map_or("-".to_owned(), |p| format!("{p:.6}"));
        let tusd = row.token_usd.map_or("-".to_owned(), fmt_usd);
        let depth = row.depth_usd.map_or("-".to_owned(), |d| format!("${d:.0}"));
        let tdepth = row
            .token_depth_usd
            .map_or("-".to_owned(), |d| format!("${d:.0}"));
        let fee = row.fee_bps.map_or(
            if row.dynamic_fee {
                "dynamic".to_owned()
            } else {
                "n/a".to_owned()
            },
            |f| format!("{}.{:02}%", f / 100, f % 100),
        );
        let act = row
            .swaps_in_window
            .map_or("-".to_owned(), |n| n.to_string());
        let note = row.note.clone().unwrap_or_default();
        println!(
            "pool-lens: [{prof}] {} pair=0x{}/0x{} fee={fee} ratio={px} token={tusd} depth={depth}+{tdepth} swaps{activity_window}={act} {note}",
            row.label,
            alloy_primitives::hex::encode(row.token0),
            alloy_primitives::hex::encode(row.token1),
        );
    }
}

/// Prints adjacent-pair spreads over USD-priced legs where both sides
/// clear the depth floor.
fn print_spreads(rows: &[LensRow], args: &PoolLensArgs) {
    let mut priced: Vec<(&LensRow, f64)> = Vec::new();
    for row in rows {
        let (Some(usd_price), Some(depth), Some(token_depth)) =
            (row.token_usd, row.depth_usd, row.token_depth_usd)
        else {
            continue;
        };
        if depth.min(token_depth) < args.min_depth_usd {
            continue;
        }
        priced.push((row, usd_price));
    }
    priced.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    if priced.len() >= 2 {
        println!("pool-lens: spreads (token USD):");
        for window in priced.windows(2) {
            let (lo, plo) = window[0];
            let (hi, phi) = window[1];
            println!(
                "pool-lens:   buy {} @ {} -> sell {} @ {} = {:+.2}% (fees/impact extra)",
                lo.label,
                fmt_usd(plo),
                hi.label,
                fmt_usd(phi),
                spread_fraction(plo, phi) * 100.0,
            );
        }
        if let (Some((_, lo)), Some((_, hi))) = (priced.first(), priced.last()) {
            println!(
                "pool-lens:   max spread {} -> {} = {sp:+.2}% on ${:.0} notional (indicative; depth + fees decide)",
                fmt_usd(*lo),
                fmt_usd(*hi),
                args.size_usd,
                sp = spread_fraction(*lo, *hi) * 100.0,
            );
        }
        return;
    }
    println!("pool-lens: fewer than two USD-priced legs — no spread matrix");
}

/// Native ETH and wrapped WETH share the native USD price on RHC.
fn is_native(address: Address) -> bool {
    address.is_zero()
        || address
            == Address::from_str("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73")
                .unwrap_or(Address::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_fraction_signs() {
        assert!((spread_fraction(1.0, 1.044) - 0.044).abs() < 1e-9);
        assert!((spread_fraction(1.0, 0.9) + 0.1).abs() < 1e-9);
        assert!(spread_fraction(0.0, 5.0).abs() < 1e-12);
        assert!(spread_fraction(-1.0, 5.0).abs() < 1e-12);
    }

    #[test]
    fn cp_output_matches_hand_computation() {
        // r0=1000, r1=1000, dx=100, no toll: 1000*100/1100 = 90.909...
        let out = gaps::cp_output(1000.0, 1000.0, 100.0, 0.0).expect("computes");
        assert!((out - 90.909_090_909).abs() < 1e-6);
        // 0.3% toll scales output down exactly.
        let tolled = gaps::cp_output(1000.0, 1000.0, 100.0, 0.003).expect("computes");
        assert!((tolled - out * 0.997).abs() < 1e-9);
        // Degenerate inputs fail closed.
        assert_eq!(gaps::cp_output(0.0, 1000.0, 100.0, 0.0), None);
        assert_eq!(gaps::cp_output(1000.0, 0.0, 100.0, 0.0), None);
        assert_eq!(gaps::cp_output(1000.0, 1000.0, 0.0, 0.0), None);
        assert_eq!(gaps::cp_output(1000.0, 1000.0, 100.0, 1.0), None);
        assert_eq!(gaps::cp_output(f64::INFINITY, 1000.0, 100.0, 0.0), None);
    }

    #[test]
    fn parse_price_accepts_pairs_rejects_garbage() {
        let (addr, usd) = parse_price("0x0000000000000000000000000000000000000001:2.5").unwrap();
        assert_eq!(addr, Address::with_last_byte(0x01));
        assert!((usd - 2.5).abs() < 1e-12);
        assert!(parse_price("nope").is_err());
        assert!(parse_price("0x0000000000000000000000000000000000000001:nan").is_err());
    }

    #[test]
    fn parse_hex_id_validates_length() {
        assert!(parse_hex_id(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(parse_hex_id("0x1234").is_err());
    }

    #[test]
    fn native_covers_zero_and_weth() {
        assert!(is_native(Address::ZERO));
        assert!(is_native(
            Address::from_str("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73").unwrap()
        ));
        assert!(!is_native(Address::with_last_byte(0x01)));
    }
}
