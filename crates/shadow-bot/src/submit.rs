//! Live submission: preflight, gas estimation, and broadcast of
//! `ExecutorV2.execute(token, amount, routerData, minProfit)` on RHC (4663).
//!
//! Hard rules honored here:
//! - The private key comes from the runtime environment only, never from a
//!   tracked file, and is never printed or logged.
//! - One `eth_estimateGas` per submission (never per quote).
//! - Fail closed: every preflight check must pass before `--broadcast` will
//!   sign anything.

#![allow(clippy::cast_precision_loss)]

use std::str::FromStr;

use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolValue, sol};

use simulation::{RouteElement, encode_swap_calldata};

sol! {
    #[sol(all_derives)]
    interface IExecutorV2 {
        #[allow(dead_code)]
        function execute(address token, uint256 amount, bytes routerData, uint256 minProfit) external payable;
    }
    #[sol(all_derives)]
    interface IExecutorV3 {
        function executeFlash(address token, uint256 amount, bytes legsData, uint256 minProfit) external payable;
    }
    struct FlashPoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    struct FlashSwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }
    struct FlashLegSol {
        FlashPoolKey key;
        FlashSwapParams params;
        bytes hookData;
    }
}

/// The RHC chain id — hard gate (`domain::Chain::from_id` equivalent).
pub const RHC_CHAIN_ID: u64 = 4663;

/// A parsed route submission request (from the `--route` JSON file or the
/// `trade` bridge).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RouteRequest {
    /// Input asset: `0x0000000000000000000000000000000000000000` = native.
    #[serde(rename = "token")]
    pub token: Address,
    /// Optimal input in wei (native or ERC20 base units).
    #[serde(rename = "amount_in")]
    pub amount_in: U256,
    /// Router-level slippage bound: minimum output of the final hop.
    #[serde(rename = "min_out", default)]
    pub min_out: U256,
    /// On-chain net-profit floor (wei of input asset). Enforces
    /// `simulated_profit > gas_cost / expected_win_rate`.
    #[serde(rename = "min_profit_wei")]
    pub min_profit_wei: U256,
    /// Unix seconds; the router reverts after it.
    #[serde(rename = "deadline", default)]
    pub deadline: Option<u64>,
    /// Route legs in swap order (see `simulation::payload_builder`).
    pub elements: Vec<LegSpec>,
}

/// One leg as written in the route JSON.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LegSpec {
    pub venue_type: u8,
    pub currency0: Address,
    pub currency1: Address,
    #[serde(default)]
    pub pool: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    #[serde(default)]
    pub hooks: Address,
    #[serde(default)]
    pub pool_manager: Address,
}

/// Result of a successful broadcast.
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    pub tx_hash: alloy_primitives::TxHash,
    pub status: u64,
    pub gas_used: u64,
    pub effective_gas_price_gwei: f64,
}

/// Everything needed to sign and send.
pub struct Submitter {
    provider: RootProvider<Ethereum>,
    signer: PrivateKeySigner,
    pub executor: Address,
    pub wallet: Address,
    rpc_url: String,
}

impl Submitter {
    /// Build a submitter from the RPC URL and the key *value* (env-sourced).
    ///
    /// # Errors
    /// Fails on a malformed URL, key, or connection setup.
    pub fn new(rpc_url: &str, key: &str, executor: Address) -> Result<Self, String> {
        let signer = PrivateKeySigner::from_str(key)
            .map_err(|_| "invalid private key material (not reported)")?;
        let wallet: Address = signer.address();
        let provider = RootProvider::<Ethereum>::new_http(
            rpc_url.parse().map_err(|e| format!("bad rpc url: {e}"))?,
        );
        Ok(Self {
            provider,
            signer,
            executor,
            wallet,
            rpc_url: rpc_url.to_owned(),
        })
    }

    /// Read-only provider handle for the trade bridge's fee/override reads.
    #[must_use]
    pub fn provider_ref(&self) -> &RootProvider<Ethereum> {
        &self.provider
    }

    /// Chain id must be RHC 4663.
    ///
    /// # Errors
    /// Fails on transport error or a non-4663 chain.
    pub async fn check_chain(&self) -> Result<u64, String> {
        let id = self
            .provider
            .get_chain_id()
            .await
            .map_err(|e| format!("chain-id read failed: {e}"))?;
        if id != RHC_CHAIN_ID {
            return Err(format!("chain id {id} != {RHC_CHAIN_ID} (RHC) — refusing"));
        }
        Ok(id)
    }

    /// The executor must be a live contract.
    ///
    /// # Errors
    /// Fails on transport error or empty code.
    pub async fn check_executor_code(&self) -> Result<usize, String> {
        let code = self
            .provider
            .get_code_at(self.executor)
            .await
            .map_err(|e| format!("code read failed: {e}"))?;
        if code.is_empty() {
            return Err(format!("no code at executor {:#?}", self.executor));
        }
        Ok(code.len())
    }

    /// Wallet gas balance must cover `min_gas_wei`.
    ///
    /// # Errors
    /// Fails on transport error or insufficient balance.
    pub async fn check_wallet_gas(&self, min_gas_wei: U256) -> Result<U256, String> {
        let bal = self
            .provider
            .get_balance(self.wallet)
            .await
            .map_err(|e| format!("balance read failed: {e}"))?;
        if bal < min_gas_wei {
            return Err(format!(
                "wallet {:#?} balance {bal} wei < required {min_gas_wei} wei — fund before trading",
                self.wallet
            ));
        }
        Ok(bal)
    }

    /// Gas price must be under `cap_gwei` (budget protection).
    ///
    /// # Errors
    /// Fails on transport error or a price above the cap.
    pub async fn check_gas_price(&self, cap_gwei: f64) -> Result<u128, String> {
        let gp = self
            .provider
            .get_gas_price()
            .await
            .map_err(|e| format!("gas price read failed: {e}"))?;
        let gwei = gp as f64 / 1e9;
        if gwei > cap_gwei {
            return Err(format!(
                "gas price {gwei:.3} gwei exceeds cap {cap_gwei:.3} gwei — refusing (budget guard)"
            ));
        }
        Ok(gp)
    }

    /// The executor must hold the input asset (`amount` plus gas headroom for
    /// native input).
    ///
    /// # Errors
    /// Fails on transport error or insufficient executor balance.
    pub async fn check_executor_funded(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<U256, String> {
        let bal = if token.is_zero() {
            self.provider
                .get_balance(self.executor)
                .await
                .map_err(|e| format!("executor balance read failed: {e}"))?
        } else {
            // balanceOf(selector 0x70a08231) — one read per submission, not per quote
            let mut data = Vec::with_capacity(36);
            data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
            data.extend_from_slice(&addr_word(self.executor));
            let res = self
                .provider
                .call(TransactionRequest::default().to(token).input(
                    alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data)),
                ))
                .await
                .map_err(|e| format!("balanceOf failed: {e}"))?;
            U256::from_be_bytes::<32>(
                res.as_ref()
                    .try_into()
                    .map_err(|_| "balanceOf returned odd data")?,
            )
        };
        if bal < amount {
            return Err(format!(
                "executor {:#?} holds {bal} wei of {token:#?} < input {amount} — fund the executor first",
                self.executor
            ));
        }
        Ok(bal)
    }

    /// Estimate the exact `execute` call (one estimate per submission).
    ///
    /// # Errors
    /// Fails when the call would revert on-chain (minProfit, route, funding).
    pub async fn estimate_execute(
        &self,
        req: &RouteRequest,
        router_data: &[u8],
    ) -> Result<u64, String> {
        let call = IExecutorV2::executeCall {
            token: req.token,
            amount: req.amount_in,
            routerData: Bytes::from(router_data.to_vec()),
            minProfit: req.min_profit_wei,
        };
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .value(if req.token.is_zero() {
                req.amount_in
            } else {
                U256::ZERO
            })
            .input(alloy_rpc_types_eth::TransactionInput::new(Bytes::from(
                abi_encode_execute(&call),
            )));
        let est = self
            .provider
            .estimate_gas(tx)
            .await
            .map_err(|e| format!("execute would revert (estimate): {e}"))?;
        Ok(est)
    }

    /// Sign, broadcast, and wait for the receipt.
    ///
    /// # Errors
    /// Fails on signing, transport, or an on-chain revert.
    pub async fn broadcast_execute(
        &self,
        req: &RouteRequest,
        router_data: &[u8],
        gas_estimate: u64,
    ) -> Result<BroadcastResult, String> {
        let call = IExecutorV2::executeCall {
            token: req.token,
            amount: req.amount_in,
            routerData: Bytes::from(router_data.to_vec()),
            minProfit: req.min_profit_wei,
        };
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .value(if req.token.is_zero() {
                req.amount_in
            } else {
                U256::ZERO
            })
            .input(alloy_rpc_types_eth::TransactionInput::new(Bytes::from(
                abi_encode_execute(&call),
            )))
            .gas_limit(gas_estimate + gas_estimate / 4); // 25% headroom
        let wallet = EthereumWallet::new(self.signer.clone());
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(
            self.rpc_url
                .parse()
                .map_err(|e| format!("bad rpc url: {e}"))?,
        );
        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("broadcast failed: {e}"))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| format!("receipt wait failed: {e}"))?;
        Ok(BroadcastResult {
            tx_hash,
            status: u64::from(receipt.status()),
            gas_used: receipt.gas_used,
            effective_gas_price_gwei: receipt.effective_gas_price as f64 / 1e9,
        })
    }

    /// Estimate `ExecutorV3.executeFlash`.
    pub async fn estimate_flash(
        &self,
        token: Address,
        amount: U256,
        legs_data: &[u8],
        min_profit: U256,
    ) -> Result<u64, String> {
        let call = IExecutorV3::executeFlashCall {
            token,
            amount,
            legsData: Bytes::from(legs_data.to_vec()),
            minProfit: min_profit,
        };
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .input(alloy_rpc_types_eth::TransactionInput::new(Bytes::from(
                call.abi_encode(),
            )));
        self.provider
            .estimate_gas(tx)
            .await
            .map_err(|e| format!("flash execute would revert (estimate): {e}"))
    }

    /// Broadcast `ExecutorV3.executeFlash`.
    pub async fn broadcast_flash(
        &self,
        token: Address,
        amount: U256,
        legs_data: &[u8],
        min_profit: U256,
        gas_estimate: u64,
    ) -> Result<BroadcastResult, String> {
        let call = IExecutorV3::executeFlashCall {
            token,
            amount,
            legsData: Bytes::from(legs_data.to_vec()),
            minProfit: min_profit,
        };
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .input(alloy_rpc_types_eth::TransactionInput::new(Bytes::from(
                call.abi_encode(),
            )))
            .gas_limit(gas_estimate + gas_estimate / 4);
        let wallet = EthereumWallet::new(self.signer.clone());
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(
            self.rpc_url
                .parse()
                .map_err(|e| format!("bad rpc url: {e}"))?,
        );
        let pending = provider
            .send_transaction(tx)
            .await
            .map_err(|e| format!("broadcast failed: {e}"))?;
        let tx_hash = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| format!("receipt wait failed: {e}"))?;
        Ok(BroadcastResult {
            tx_hash,
            status: u64::from(receipt.status()),
            gas_used: receipt.gas_used,
            effective_gas_price_gwei: receipt.effective_gas_price as f64 / 1e9,
        })
    }

    /// Full fail-closed pipeline: preflight → encode → estimate.
    ///
    /// # Errors
    /// Any failed gate aborts before signing.
    pub async fn prepare(
        &self,
        req: &RouteRequest,
        gas_cap_gwei: f64,
        min_gas_headroom_wei: U256,
    ) -> Result<(Vec<u8>, u64, u128), String> {
        self.check_chain().await?;
        let code_len = self.check_executor_code().await?;
        eprintln!("preflight: chain ok, executor code {code_len} bytes");
        let gp = self.check_gas_price(gas_cap_gwei).await?;
        eprintln!("preflight: gas price {:.4} gwei under cap", gp as f64 / 1e9);
        if req.token.is_zero() {
            // Native input arrives as msg.value — the executor needs no
            // pre-funding; the wallet must cover input + gas instead.
            eprintln!("preflight: native input, funded by msg.value (no executor balance needed)");
        } else {
            self.check_executor_funded(req.token, req.amount_in).await?;
        }
        let router_data = encode_swap_calldata(
            &route_elements(req),
            req.amount_in,
            req.min_out,
            U256::from(req.deadline.unwrap_or_default()),
        )?;
        let est = self.estimate_execute(req, &router_data).await?;
        eprintln!("preflight: execute estimates {est} gas");
        // ~2x estimate headroom in wei terms at the observed price.
        let need = U256::from(est.saturating_mul(2)) * U256::from(gp);
        self.check_wallet_gas(min_gas_headroom_wei.max(need))
            .await?;
        Ok((router_data, est, gp))
    }
}

/// ABI-encode the executor `execute` call without pulling `alloy-contract`.
fn abi_encode_execute(call: &IExecutorV2::executeCall) -> Vec<u8> {
    let mut out =
        alloy_primitives::keccak256("execute(address,uint256,bytes,uint256)")[0..4].to_vec();
    // static head: token, amount, offset to routerData (0x80), minProfit
    out.extend_from_slice(&addr_word(call.token));
    out.extend_from_slice(&call.amount.to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(0x80u32).to_be_bytes::<32>());
    out.extend_from_slice(&call.minProfit.to_be_bytes::<32>());
    // dynamic bytes: length + padded payload
    out.extend_from_slice(&U256::from(call.routerData.len()).to_be_bytes::<32>());
    out.extend_from_slice(&call.routerData);
    let pad = call.routerData.len().next_multiple_of(32) - call.routerData.len();
    out.resize(out.len() + pad, 0);
    out
}

fn addr_word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(a.as_slice());
    w
}

#[must_use]
pub fn route_elements(req: &RouteRequest) -> Vec<RouteElement> {
    req.elements
        .iter()
        .map(|l| RouteElement {
            venue_type: l.venue_type,
            currency0: l.currency0,
            currency1: l.currency1,
            pool: l.pool,
            fee: l.fee,
            tick_spacing: l.tick_spacing,
            hooks: l.hooks,
            pool_manager: l.pool_manager,
            pool_key: [0u8; 32],
            hook_data: Vec::new(),
        })
        .collect()
}

/// Build `FlashLeg[]` abi-encoded bytes for `ExecutorV3.executeFlash` from a
/// `GatedRow`. Only V4 legs are supported in flash mode (V3 needs a separate callback).
///
/// # Errors
/// Fails if any leg is not V4 or lacks tick/hooks overrides.
pub fn build_flash_legs_data(
    row: &trade::GatedRow,
    overrides: &std::collections::HashMap<String, (i32, Address)>,
) -> Result<Vec<u8>, String> {
    use alloy_sol_types::SolValue;
    let mut legs: Vec<FlashLegSol> = Vec::with_capacity(row.legs.len());
    for leg in &row.legs {
        let (profile, _pool, pool_id, tin, tout, fee_raw) = trade::parse_leg(leg)?;
        if profile != "v4" {
            return Err(format!("flash mode requires V4 legs; got {profile} pool {leg}"));
        }
        let key = alloy_primitives::hex::encode(pool_id);
        let Some((tick, hooks)) = overrides.get(&key) else {
            return Err(format!("V4 pool {key} missing tick/hooks override"));
        };
        // V4 PoolKey currencies are sorted
        let (c0, c1) = if tin < tout { (tin, tout) } else { (tout, tin) };
        let zero_for_one = tin == c0;
        legs.push(FlashLegSol {
            key: FlashPoolKey {
                currency0: c0,
                currency1: c1,
                fee: alloy_primitives::Uint::<24, 1>::from(fee_raw),
                tickSpacing: alloy_primitives::Signed::<24, 1>::try_from(*tick).unwrap(),
                hooks: *hooks,
            },
            params: FlashSwapParams {
                zeroForOne: zero_for_one,
                amountSpecified: alloy_primitives::I256::ZERO, // set in contract to curAmount
                sqrtPriceLimitX96: alloy_primitives::U160::ZERO,
            },
            hookData: alloy_primitives::Bytes::new(),
        });
    }
    Ok(legs.abi_encode())
}

/// CLI glue for `submit-exec`.
pub mod command {
    use super::{RouteRequest, Submitter};
    use alloy_primitives::Address;
    use std::path::Path;

    /// # Errors
    /// Any preflight failure, malformed route, or (with `--broadcast`) a
    /// failed signing/broadcast/receipt. Never broadcasts without all gates.
    pub async fn submit_exec_command(
        rpc: &str,
        executor: &str,
        route: &Path,
        gas_cap_gwei: f64,
        broadcast: bool,
    ) -> Result<(), String> {
        let key = std::env::var("ARBITRAGE_WALLET_PRIVATE_KEY")
            .map_err(|_| "ARBITRAGE_WALLET_PRIVATE_KEY not set in the environment".to_owned())?;
        let executor: Address = executor
            .parse()
            .map_err(|e| format!("bad executor address: {e}"))?;
        let text =
            std::fs::read_to_string(route).map_err(|e| format!("route file unreadable: {e}"))?;
        let req: RouteRequest =
            serde_json::from_str(&text).map_err(|e| format!("route JSON invalid: {e}"))?;
        if req.min_profit_wei.is_zero() {
            return Err(
                "refusing: min_profit_wei is zero (submission gate floor required)".to_owned(),
            );
        }
        if req.deadline.is_none() {
            return Err("refusing: deadline is required (stale-route protection)".to_owned());
        }
        let submitter = Submitter::new(rpc, &key, executor)?;
        eprintln!(
            "submit-exec: wallet {:#?} executor {executor:#?} broadcast={broadcast}",
            submitter.wallet
        );
        let (router_data, est, _gp) = submitter
            .prepare(&req, gas_cap_gwei, alloy_primitives::U256::ZERO)
            .await?;
        eprintln!(
            "submit-exec: router_data {} bytes, estimate {est} gas",
            router_data.len()
        );
        if !broadcast {
            eprintln!("submit-exec: DRY RUN (no --broadcast) — all gates passed, nothing sent");
            return Ok(());
        }
        let result = submitter.broadcast_execute(&req, &router_data, est).await?;
        println!(
            "submit-exec: TX {} status {} gas_used {} @ {:.4} gwei",
            result.tx_hash, result.status, result.gas_used, result.effective_gas_price_gwei
        );
        if result.status != 1 {
            return Err(format!("tx reverted on-chain: {}", result.tx_hash));
        }
        Ok(())
    }

    /// `trade` CLI glue: tail the run-pairs CSV and execute gate-passing rows.
    use super::trade::{CsvTailer, attempt};
    use std::time::Duration;

    /// # Errors
    /// Fatal setup errors (bad address, unreadable files). Per-row failures
    /// are logged and skipped — one bad row must not stop the tail.
    #[allow(clippy::too_many_arguments)]
    pub async fn trade_command(
        rpc: &str,
        executor: &str,
        csv: &Path,
        overrides: Option<&Path>,
        flash: bool,
        prices: &Path,
        win_rate_pct: u64,
        native_usd: u64,
        gas_cap_gwei: f64,
        slippage_bps: u64,
        profit_safety_pct: u64,
        deadline_secs: u64,
        poll_ms: u64,
        max_attempts: u64,
        broadcast: bool,
    ) -> Result<(), String> {
        let key = std::env::var("ARBITRAGE_WALLET_PRIVATE_KEY")
            .map_err(|_| "ARBITRAGE_WALLET_PRIVATE_KEY not set in the environment".to_owned())?;
        let executor: Address = executor
            .parse()
            .map_err(|e| format!("bad executor address: {e}"))?;
        let submitter = super::Submitter::new(rpc, &key, executor)?;
        let prices = crate::gaps::load_prices(prices)?;
        eprintln!(
            "trade: loaded {} token prices for the gas floor",
            prices.len()
        );
        let overrides = match overrides {
            Some(path) => super::trade::load_overrides(path)?,
            None => std::collections::HashMap::new(),
        };
        let mut tailer = CsvTailer::default();
        // Start from the current end of file: only NEW gated rows are traded.
        let len = std::fs::metadata(csv)
            .map_err(|e| format!("csv metadata: {e}"))?
            .len();
        tailer.skip_to(len);
        eprintln!(
            "trade: wallet {:#?} executor {executor:#?} flash={flash} broadcast={broadcast} overrides={} tailing {}",
            submitter.wallet,
            overrides.len(),
            csv.display()
        );
        let mut attempts: u64 = 0;
        loop {
            if max_attempts > 0 && attempts >= max_attempts {
                eprintln!("trade: attempt cap {max_attempts} reached; stopping");
                return Ok(());
            }
            let rows = match tailer.poll(csv) {
                Ok(rows) => rows,
                Err(e) => {
                    eprintln!("trade: csv poll failed: {e}");
                    tokio::time::sleep(Duration::from_millis(poll_ms)).await;
                    continue;
                }
            };
            for line in rows {
                let row = match super::trade::parse_row(&line) {
                    Ok(Some(row)) => row,
                    Ok(None) => continue,
                    Err(e) => {
                        eprintln!("trade: skipping malformed row: {e}");
                        continue;
                    }
                };
                eprintln!(
                    "trade: GATED {} anchor {:#?} input {} profit {} ({} legs)",
                    row.kind,
                    row.token_lo,
                    row.input,
                    row.profit,
                    row.legs.len()
                );
                match attempt(
                    &submitter,
                    &row,
                    &overrides,
                    &prices,
                    win_rate_pct,
                    native_usd,
                    gas_cap_gwei,
                    slippage_bps,
                    profit_safety_pct,
                    deadline_secs,
                    broadcast,
                    flash,
                )
                .await
                {
                    Ok(outcome) => {
                        attempts += u64::from(!outcome.dry_run);
                        println!("trade: EXECUTED dry={} {}", outcome.dry_run, outcome.detail);
                    }
                    Err(e) => {
                        // Fail-closed per row: log and keep the tail alive.
                        eprintln!("trade: attempt refused: {e}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(poll_ms)).await;
        }
    }
}

/// The automated detect → gate → execute bridge.
pub mod trade {
    use super::{RouteRequest, Submitter};
    use alloy_primitives::{Address, U256};
    use simulation::RouteElement;

    use std::io::{Seek, SeekFrom};
    use std::path::Path;

    /// One parsed gate-passing CSV row, ready to become a route.
    #[derive(Debug, Clone)]
    pub struct GatedRow {
        pub kind: String,
        pub token_lo: Address,
        pub input: U256,
        pub output: U256,
        pub profit: U256,
        pub legs: Vec<String>,
    }

    /// Incremental CSV tailer: remembers the byte offset, yields only new rows.
    #[derive(Debug, Default)]
    pub struct CsvTailer {
        offset: u64,
    }

    impl CsvTailer {
        /// Start tailing from an absolute byte offset (used to skip the
        /// pre-existing file content so only fresh rows are traded).
        pub fn skip_to(&mut self, offset: u64) {
            self.offset = offset;
        }

        /// Read rows appended since the last call. Header lines and empty
        /// lines are skipped; partial trailing lines (flush mid-write) are
        /// left for the next poll.
        ///
        /// # Errors
        /// Fails when the file cannot be read or seeked.
        pub fn poll(&mut self, path: &Path) -> Result<Vec<String>, String> {
            let mut f = std::fs::File::open(path).map_err(|e| format!("csv open: {e}"))?;
            let len = f
                .metadata()
                .map_err(|e| format!("csv metadata: {e}"))?
                .len();
            if len <= self.offset {
                return Ok(Vec::new());
            }
            f.seek(SeekFrom::Start(self.offset))
                .map_err(|e| format!("csv seek: {e}"))?;
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut f, &mut buf)
                .map_err(|e| format!("csv read: {e}"))?;
            let mut lines: Vec<String> = Vec::new();
            let mut consumed = self.offset;
            for line in buf.split_inclusive('\n') {
                let complete = line.ends_with('\n');
                if complete {
                    consumed += line.len() as u64;
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with("kind,") {
                        lines.push(t.to_owned());
                    }
                }
            }
            self.offset = consumed;
            Ok(lines)
        }
    }

    /// Parse one CSV row into a [`GatedRow`]. The `legs` column is last and
    /// pipe-separated per leg.
    ///
    /// # Errors
    /// Fails on malformed rows.
    pub fn parse_row(line: &str) -> Result<Option<GatedRow>, String> {
        let cols: Vec<&str> = line.split(',').collect();
        // kind,token_lo,token_hi,to_block,input,output,profit,log2_skew,...,anchor_priced,legs
        // reason_code is column 15 (0-based); legs is the last column.
        if cols.len() < 19 {
            return Ok(None);
        }
        if cols[15] != "above_threshold" {
            return Ok(None);
        }
        let Some(legs_col) = cols.get(18) else {
            return Err("row has no legs column".to_owned());
        };
        let parse_u = |s: &str| -> Result<U256, String> {
            U256::from_str_radix(s, 10).map_err(|e| format!("bad number {s}: {e}"))
        };
        // legs may itself contain no commas (encode_csv uses ':' and '|').
        let legs: Vec<String> = legs_col
            .split('|')
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        Ok(Some(GatedRow {
            kind: cols[0].to_owned(),
            token_lo: cols[1].parse().map_err(|e| format!("bad token_lo: {e}"))?,
            input: parse_u(cols[4])?,
            output: parse_u(cols[5])?,
            profit: parse_u(cols[6])?,
            legs,
        }))
    }

    /// One parsed leg: `(profile, pool, pool_id, token_in, token_out, fee_raw)`.
    pub type ParsedLeg = (String, Address, [u8; 32], Address, Address, u32);

    /// Parse one `<profile>:<pool>:<pool_id>:<token_in>:<token_out>:<fee>` leg.
    ///
    /// # Errors
    /// Fails on malformed fields.
    pub fn parse_leg(s: &str) -> Result<ParsedLeg, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(format!("leg needs 6 fields, got {}: {s}", parts.len()));
        }
        let mut pool_id = [0u8; 32];
        let id_hex =
            alloy_primitives::hex::decode(parts[2]).map_err(|e| format!("bad pool_id: {e}"))?;
        if id_hex.len() == 32 {
            pool_id.copy_from_slice(&id_hex);
        }
        let tin: Address = parts[3].parse().map_err(|e| format!("bad token_in: {e}"))?;
        let tout: Address = parts[4]
            .parse()
            .map_err(|e| format!("bad token_out: {e}"))?;
        let fee: u32 = parts[5].parse().map_err(|e| format!("bad fee: {e}"))?;
        let pool_addr: Address = parts[1].parse().map_err(|e| format!("bad pool: {e}"))?;
        Ok((parts[0].to_owned(), pool_addr, pool_id, tin, tout, fee))
    }

    /// On-chain V3 pool `fee()` (selector `0xddca3f43`) — the CSV fee column
    /// is not trustworthy (measured mismatch on pool 0x03cC14c8, 2026-08-30).
    async fn read_v3_fee(
        provider: &alloy_provider::RootProvider<alloy_network::Ethereum>,
        pool: Address,
    ) -> Result<u32, String> {
        use alloy_provider::Provider as _;
        use alloy_rpc_types_eth::TransactionInput;
        let res = provider
            .call(
                alloy_rpc_types_eth::TransactionRequest::default()
                    .to(pool)
                    .input(TransactionInput::new(alloy_primitives::Bytes::from([
                        0xdd, 0xca, 0x3f, 0x43,
                    ]))),
            )
            .await
            .map_err(|e| format!("fee() read failed for {pool:#?}: {e}"))?;
        if res.as_ref().len() < 32 {
            return Err(format!(
                "fee() returned {} bytes for {pool:#?}",
                res.as_ref().len()
            ));
        }
        Ok(u32::from_be_bytes(
            res.as_ref()[28..32].try_into().expect("32-byte word tail"),
        ))
    }

    /// V4 pool overrides: `pool_id_hex,tick_spacing,hooks_hex` per line.
    pub fn load_overrides(
        path: &Path,
    ) -> Result<std::collections::HashMap<String, (i32, Address)>, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("overrides unreadable: {e}"))?;
        let mut map = std::collections::HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("pool_id") {
                continue;
            }
            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() != 3 {
                continue;
            }
            let tick: i32 = cols[1].parse().map_err(|e| format!("bad tick: {e}"))?;
            // Hooks may be stored unpadded ("0x" for zero) — left-pad to 40 hex.
            let raw = cols[2].trim_start_matches("0x").trim_start_matches("0X");
            let padded = format!("{raw:0>40}");
            let hooks: Address = padded
                .parse()
                .map_err(|e| format!("bad hooks {}: {e}", cols[2]))?;
            map.insert(cols[0].to_lowercase(), (tick, hooks));
        }
        Ok(map)
    }

    /// Convert CSV legs into router `RouteElement`s, resolving V3 fees on-chain
    /// and requiring V4 overrides.
    ///
    /// # Errors
    /// Fails closed on unknown V4 components or a failed fee read.
    #[allow(clippy::too_many_lines)]
    pub async fn build_elements(
        provider: &alloy_provider::RootProvider<alloy_network::Ethereum>,
        row: &GatedRow,
        overrides: &Overrides,
    ) -> Result<Vec<RouteElement>, String> {
        let mut out = Vec::with_capacity(row.legs.len());
        for leg in &row.legs {
            let (profile, pool, pool_id, tin, tout, fee_raw) = parse_leg(leg)?;
            match profile.as_str() {
                "v3" => {
                    let fee = read_v3_fee(provider, pool).await?;
                    let tick = crate::gaps::tick_spacing_from_fee(fee);
                    out.push(RouteElement::v3(tin, tout, pool, fee, tick));
                }
                "v4" => {
                    let key = alloy_primitives::hex::encode(pool_id);
                    let Some((tick, hooks)) = overrides.get(&key) else {
                        return Err(format!(
                            "refusing: V4 pool {key} has no tick/hooks override — run scripts/enrich_v4.py first"
                        ));
                    };
                    out.push(RouteElement::v4(tin, tout, fee_raw, *tick, *hooks));
                }
                other => return Err(format!("unknown venue profile {other:?}")),
            }
        }
        Ok(out)
    }

    /// One trade attempt summary.
    #[derive(Debug)]
    pub struct TradeOutcome {
        pub dry_run: bool,
        pub detail: String,
    }

    type Overrides = std::collections::HashMap<String, (i32, Address)>;

    /// Attempt one gated row: build route → preflight → (optionally) broadcast.
    ///
    /// The on-chain `minProfit` is `max(quoted profit × safety, gas floor)`:
    /// the gas floor expresses `gas_cost / win_rate` in input-token terms so a
    /// tiny-quoted episode can never pass at a net loss (SECURITY.md gate).
    ///
    /// # Errors
    /// Any gate failure aborts before signing (fail-closed).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn attempt(
        submitter: &Submitter,
        row: &GatedRow,
        overrides: &Overrides,
        prices: &std::collections::HashMap<Address, U256>,
        win_rate_pct: u64,
        native_usd: u64,
        gas_cap_gwei: f64,
        slippage_bps: u64,
        profit_safety_pct: u64,
        deadline_secs: u64,
        broadcast: bool,
        flash: bool,
    ) -> Result<TradeOutcome, String> {
        if flash {
            let token = row.token_lo;
            let legs_data = crate::submit::build_flash_legs_data(row, overrides)?;
            let mut min_profit =
                row.profit.saturating_mul(U256::from(profit_safety_pct)) / U256::from(100_u64);
            // Preflight: chain, code, gas price
            submitter.check_chain().await?;
            let code_len = submitter.check_executor_code().await?;
            eprintln!("preflight (flash): chain ok, executor code {code_len} bytes");
            let gas_price_wei = submitter.check_gas_price(gas_cap_gwei).await?;
            eprintln!(
                "preflight (flash): gas price {:.4} gwei under cap",
                gas_price_wei as f64 / 1e9
            );
            // Estimate with quoted minProfit to learn gas, then enforce floor
            let mut est = submitter
                .estimate_flash(token, row.input, &legs_data, min_profit)
                .await?;
            eprintln!("preflight (flash): estimate {est} gas");
            // Gas floor
            let token_usd = prices.get(&token).copied();
            if let Some(usd) = token_usd.filter(|u| !u.is_zero()) {
                let native_usd_wei =
                    U256::from(native_usd) * U256::from(1_000_000_000_000_000_000_u64);
                let gas_cost_usd_wei = U256::from(est) * U256::from(gas_price_wei) * native_usd_wei
                    / U256::from(1_000_000_000_000_000_000_u64);
                let floor = gas_cost_usd_wei * U256::from(100_u64)
                    / U256::from(win_rate_pct.max(1))
                    * U256::from(1_000_000_000_000_000_000_u64)
                    / usd;
                if floor > min_profit {
                    eprintln!("trade (flash): gas floor binds {min_profit} -> {floor}");
                    min_profit = floor;
                    est = submitter
                        .estimate_flash(token, row.input, &legs_data, min_profit)
                        .await?;
                    eprintln!("preflight (flash): re-estimate {est} gas with floor");
                }
            }
            let need = U256::from(est.saturating_mul(2)) * U256::from(gas_price_wei);
            submitter.check_wallet_gas(need).await?;
            if !broadcast {
                return Ok(TradeOutcome {
                    dry_run: true,
                    detail: format!("gates passed (flash), estimate {est} gas (dry run)"),
                });
            }
            let result = submitter
                .broadcast_flash(token, row.input, &legs_data, min_profit, est)
                .await?;
            return Ok(TradeOutcome {
                dry_run: false,
                detail: format!("TX {} status {} gas {}", result.tx_hash, result.status, result.gas_used),
            });
        }
        let elements = build_elements(submitter.provider_ref(), row, overrides).await?;
        let token = row.token_lo;
        let min_out = {
            if slippage_bps >= 10_000 {
                return Err("slippage-bps must be below 10000".to_owned());
            }
            row.output
                .saturating_mul(U256::from(10_000_u64 - slippage_bps))
                / U256::from(10_000_u64)
        };
        let min_profit =
            row.profit.saturating_mul(U256::from(profit_safety_pct)) / U256::from(100_u64);
        let req = RouteRequest {
            token,
            amount_in: row.input,
            min_out,
            min_profit_wei: min_profit,
            deadline: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_secs()
                    + deadline_secs,
            ),
            elements: elements
                .iter()
                .map(|e| super::LegSpec {
                    venue_type: e.venue_type,
                    currency0: e.currency0,
                    currency1: e.currency1,
                    pool: e.pool,
                    fee: e.fee,
                    tick_spacing: e.tick_spacing,
                    hooks: e.hooks,
                    pool_manager: e.pool_manager,
                })
                .collect(),
        };
        let (router_data, est, gas_price_wei) =
            submitter.prepare(&req, gas_cap_gwei, U256::ZERO).await?;

        // Gas floor in input-token wei: gas_cost_usd / win_rate converted via
        // the token's 1e18-scaled USD price. No price → refuse (fail-closed).
        let token_usd = prices.get(&token).copied();
        let quoted_min = min_profit;
        let floor_min = match token_usd {
            Some(usd) if !usd.is_zero() => {
                let native_usd_wei =
                    U256::from(native_usd) * U256::from(1_000_000_000_000_000_000_u64);
                let gas_cost_usd_wei = U256::from(est) * U256::from(gas_price_wei) * native_usd_wei
                    / U256::from(1_000_000_000_000_000_000_u64);
                gas_cost_usd_wei * U256::from(100_u64) / U256::from(win_rate_pct.max(1))
                    * U256::from(1_000_000_000_000_000_000_u64)
                    / usd
            }
            _ => {
                return Err(format!(
                    "refusing: input token {token:#?} has no USD price — cannot size the gas floor"
                ));
            }
        };
        let min_profit = quoted_min.max(floor_min);
        if min_profit != quoted_min {
            eprintln!(
                "trade: gas floor binds — minProfit raised {quoted_min} -> {min_profit} (gas {est} @ {gas_price_wei} wei, win {win_rate_pct}%)"
            );
            // Re-encode with the floor as the on-chain minProfit; gas usage is
            // unchanged (the floor only tightens the final balance check), so
            // the estimate is reused.
            let req = RouteRequest {
                min_profit_wei: min_profit,
                ..req
            };
            let (router_data, est, _) = submitter.prepare(&req, gas_cap_gwei, U256::ZERO).await?;
            if !broadcast {
                return Ok(TradeOutcome {
                    dry_run: true,
                    detail: format!("gates passed with gas floor {min_profit} wei (dry run)"),
                });
            }
            let result = submitter.broadcast_execute(&req, &router_data, est).await?;
            return Ok(TradeOutcome {
                dry_run: false,
                detail: format!(
                    "TX {} status {} gas {}",
                    result.tx_hash, result.status, result.gas_used
                ),
            });
        }
        if !broadcast {
            return Ok(TradeOutcome {
                dry_run: true,
                detail: format!("gates passed, estimate {est} gas (dry run)"),
            });
        }
        let result = submitter.broadcast_execute(&req, &router_data, est).await?;
        Ok(TradeOutcome {
            dry_run: false,
            detail: format!(
                "TX {} status {} gas {}",
                result.tx_hash, result.status, result.gas_used
            ),
        })
    }
}
