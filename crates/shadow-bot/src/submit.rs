//! Live submission: preflight, gas estimation, and broadcast of executor
//! entries on RHC (4663) — `ExecutorV3` float (`executeFlash`/`executeHybrid`)
//! and `ExecutorV4Morpho` flash (`executeMorphoFlash`/`executeMorphoHybrid`).
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
use alloy_sol_types::sol;

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
        function executeHybrid(address token, uint256 amount, bytes legsData, uint256 minProfit) external payable;
    }
    #[sol(all_derives)]
    interface IExecutorV4 {
        function executeMorphoFlash(address token, uint256 amount, bytes legsData, uint256 minProfit) external;
        function executeMorphoHybrid(address token, uint256 amount, bytes legsData, uint256 minProfit) external;
    }
    /// Compact route leg for the router-based `ExecutorV3` (mirrors
    /// `contracts/ExecutorV3.sol` `RouteLeg` field-for-field).
    struct RouteLegSol {
        uint8 venue;
        address v3Pool;
        address inTok;
        address outTok;
        bool zeroForOne;
        uint160 sqrtPriceLimitX96;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
        bytes hookData;
    }
}

/// The RHC chain id — hard gate (`domain::Chain::from_id` equivalent).
pub const RHC_CHAIN_ID: u64 = 4663;

/// Keyless ERC20 `balanceOf(holder)` (or native balance for `0x0`).
///
/// # Errors
/// Fails on transport error or malformed return data.
pub async fn erc20_balance_of(
    provider: &RootProvider<Ethereum>,
    token: Address,
    holder: Address,
) -> Result<U256, String> {
    if token.is_zero() {
        return provider
            .get_balance(holder)
            .await
            .map_err(|e| format!("native balance read failed: {e}"));
    }
    // balanceOf(selector 0x70a08231)
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
    data.extend_from_slice(&addr_word(holder));
    let res = provider
        .call(TransactionRequest::default().to(token).input(
            alloy_rpc_types_eth::TransactionInput::new(Bytes::from(data)),
        ))
        .await
        .map_err(|e| format!("balanceOf failed: {e}"))?;
    Ok(U256::from_be_bytes::<32>(
        res.as_ref()
            .try_into()
            .map_err(|_| "balanceOf returned odd data")?,
    ))
}

/// Morpho Blue singleton on RHC — the flash lender (verified 2026-09-05:
/// official Morpho addresses page + onchain `flashLoan` selector).
pub const MORPHO_BLUE: Address = Address::new([
    0x9D, 0x53, 0xd5, 0xE3, 0xbd, 0x5E, 0x8d, 0x4C, 0xbf, 0xa6, 0xDB, 0x1c, 0xa2, 0x38, 0xAE, 0xA0,
    0x2E, 0x65, 0x10, 0x10,
]);

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

    /// ERC20 `balanceOf(holder)` (or native balance for `0x0`) — one read,
    /// never per quote.
    ///
    /// # Errors
    /// Fails on transport error or malformed return data.
    pub async fn token_balance_of(&self, token: Address, holder: Address) -> Result<U256, String> {
        erc20_balance_of(&self.provider, token, holder).await
    }

    /// The executor must hold the input asset (float mode only).
    ///
    /// # Errors
    /// Fails on transport error or insufficient executor balance.
    pub async fn check_executor_funded(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<U256, String> {
        let bal = self.token_balance_of(token, self.executor).await?;
        if bal < amount {
            return Err(format!(
                "executor {:#?} holds {bal} wei of {token:#?} < input {amount} (float mode) — seed the float or use --capital-source morpho",
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

    /// Estimate any executor entry point (one estimate per submission).
    ///
    /// # Errors
    /// Fails when the call would revert on-chain (minProfit, route, funding).
    pub async fn estimate_entry(
        &self,
        entry: trade::EntryPoint,
        token: Address,
        amount: U256,
        legs_data: &[u8],
        min_profit: U256,
    ) -> Result<u64, String> {
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .input(alloy_rpc_types_eth::TransactionInput::new(
                entry.encode(token, amount, legs_data, min_profit),
            ));
        self.provider
            .estimate_gas(tx)
            .await
            .map_err(|e| format!("{} would revert (estimate): {e}", entry.describe()))
    }

    /// Sign, broadcast, and wait for the receipt of any executor entry point.
    ///
    /// # Errors
    /// Fails on signing, transport, or an on-chain revert.
    pub async fn broadcast_entry(
        &self,
        entry: trade::EntryPoint,
        token: Address,
        amount: U256,
        legs_data: &[u8],
        min_profit: U256,
        gas_estimate: u64,
    ) -> Result<BroadcastResult, String> {
        let tx = TransactionRequest::default()
            .from(self.wallet)
            .to(self.executor)
            .input(alloy_rpc_types_eth::TransactionInput::new(
                entry.encode(token, amount, legs_data, min_profit),
            ))
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

/// Map the wrapped-native alias back to the V4 null sentinel for `PoolKey`
/// construction. RHC V4 keys use `0x0` for the native currency while CSV legs
/// carry the wrapped contract (`gaps::RHC_NATIVE`); building a key with the
/// wrapped address derives a poolId that was never initialized
/// (`PoolNotInitialized`, `0x486aa307`). V2/V3 pools use the real contract
/// address on-chain, so this applies to V4 legs only.
fn denormalize_currency(token: Address) -> Address {
    if token == crate::gaps::RHC_NATIVE {
        Address::ZERO
    } else {
        token
    }
}

/// Build `FlashLeg[]` abi-encoded bytes for `ExecutorV3.executeFlash` from a
/// `GatedRow`. Only V4 legs are supported in flash mode (V3 needs a separate callback).
///
/// Build `RouteLeg[]` abi-encoded bytes for `ExecutorV3.executeFlash` from a
/// `GatedRow`. Only V4 legs are supported in flash mode; they execute through
/// the RHC router (never direct PM.swap).
///
/// # Errors
/// Fails if any leg is not V4 or lacks tick/hooks overrides.
pub fn build_flash_legs_data(
    row: &trade::GatedRow,
    overrides: &std::collections::HashMap<String, (i32, Address)>,
) -> Result<Vec<u8>, String> {
    use alloy_sol_types::SolValue;
    let mut legs: Vec<RouteLegSol> = Vec::with_capacity(row.legs.len());
    for leg in &row.legs {
        let (profile, _pool, pool_id, tin, tout, fee_raw) = trade::parse_leg(leg)?;
        if profile != "v4" {
            return Err(format!(
                "flash mode requires V4 legs; got {profile} pool {leg}"
            ));
        }
        let key = alloy_primitives::hex::encode(pool_id);
        let Some((tick, hooks)) = overrides.get(&key) else {
            return Err(format!("V4 pool {key} missing tick/hooks override"));
        };
        // Router convention: directional in/out with the 0x0 native sentinel.
        let tin = denormalize_currency(tin);
        let tout = denormalize_currency(tout);
        legs.push(RouteLegSol {
            venue: 1,
            v3Pool: Address::ZERO,
            inTok: tin,
            outTok: tout,
            zeroForOne: false,
            sqrtPriceLimitX96: alloy_primitives::U160::ZERO,
            fee: alloy_primitives::Uint::<24, 1>::from(fee_raw),
            tickSpacing: alloy_primitives::Signed::<24, 1>::try_from(*tick).unwrap(),
            hooks: *hooks,
            hookData: alloy_primitives::Bytes::new(),
        });
    }
    Ok(legs.abi_encode())
}

/// Build `RouteLeg[]` for `ExecutorV3.executeHybrid` — supports V3+V4 mixes.
/// V3 legs execute direct pool.swap (exact input, positive amount); V4 legs
/// execute through the RHC router with directional in/out tokens.
pub fn build_hybrid_legs_data(
    row: &trade::GatedRow,
    overrides: &std::collections::HashMap<String, (i32, Address)>,
) -> Result<Vec<u8>, String> {
    use alloy_sol_types::SolValue;
    let mut legs: Vec<RouteLegSol> = Vec::with_capacity(row.legs.len());
    for leg in &row.legs {
        let (profile, pool, pool_id, tin, tout, fee_raw) = trade::parse_leg(leg)?;
        match profile.as_str() {
            "v3" => {
                // V3 pools use real token addresses (no sentinel); direction
                // from canonical token order.
                let zero_for_one = tin < tout;
                legs.push(RouteLegSol {
                    venue: 0,
                    v3Pool: pool,
                    inTok: tin,
                    outTok: tout,
                    zeroForOne: zero_for_one,
                    sqrtPriceLimitX96: alloy_primitives::U160::ZERO,
                    fee: alloy_primitives::Uint::<24, 1>::from(fee_raw),
                    tickSpacing: alloy_primitives::Signed::<24, 1>::try_from(0).unwrap(),
                    hooks: Address::ZERO,
                    hookData: alloy_primitives::Bytes::new(),
                });
            }
            "v4" => {
                let key = alloy_primitives::hex::encode(pool_id);
                let Some((tick, hooks)) = overrides.get(&key) else {
                    return Err(format!("V4 pool {key} missing tick/hooks override"));
                };
                // Router convention: directional in/out, 0x0 native sentinel.
                let tin = denormalize_currency(tin);
                let tout = denormalize_currency(tout);
                legs.push(RouteLegSol {
                    venue: 1,
                    v3Pool: Address::ZERO,
                    inTok: tin,
                    outTok: tout,
                    zeroForOne: false,
                    sqrtPriceLimitX96: alloy_primitives::U160::ZERO,
                    fee: alloy_primitives::Uint::<24, 1>::from(fee_raw),
                    tickSpacing: alloy_primitives::Signed::<24, 1>::try_from(*tick).unwrap(),
                    hooks: *hooks,
                    hookData: alloy_primitives::Bytes::new(),
                });
            }
            other => return Err(format!("unknown venue profile {other:?}")),
        }
    }
    Ok(legs.abi_encode())
}

/// CLI glue for `submit-exec`.
pub mod command {
    use super::{RouteRequest, Submitter};
    use alloy_network::Ethereum;
    use alloy_primitives::{Address, U256};
    use alloy_provider::{Provider, RootProvider};
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
        hook_allowlist: Option<&Path>,
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
        capital_source: &str,
    ) -> Result<(), String> {
        let key = std::env::var("ARBITRAGE_WALLET_PRIVATE_KEY")
            .map_err(|_| "ARBITRAGE_WALLET_PRIVATE_KEY not set in the environment".to_owned())?;
        let capital_source = super::trade::parse_capital_source(capital_source)?;
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
        // Manifest hook policy, execution side: empty when no list is
        // given (refuse all nonzero-hook V4 pools at pre-estimate).
        let hook_allowlist = match hook_allowlist {
            Some(path) => crate::gaps::load_hook_allowlist(path)?,
            None => std::collections::HashSet::new(),
        };
        let mut tailer = CsvTailer::default();
        // Start from the current end of file: only NEW gated rows are traded.
        let len = std::fs::metadata(csv)
            .map_err(|e| format!("csv metadata: {e}"))?
            .len();
        tailer.skip_to(len);
        eprintln!(
            "trade: wallet {:#?} executor {executor:#?} flash={flash} capital={capital_source:?} broadcast={broadcast} overrides={} hook_allowlist={} tailing {}",
            submitter.wallet,
            overrides.len(),
            hook_allowlist.len(),
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
                    &hook_allowlist,
                    &prices,
                    win_rate_pct,
                    native_usd,
                    gas_cap_gwei,
                    slippage_bps,
                    profit_safety_pct,
                    deadline_secs,
                    broadcast,
                    flash,
                    capital_source,
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

    /// `verify-blue` CLI glue: one-off read proving Morpho Blue holds every
    /// `morpho`-labeled token in the support CSV (the per-trade flash
    /// ceiling). Read-only; needs no key. Exits nonzero when zero tokens are
    /// fundable — fail-closed, so a stale CSV can never look like coverage.
    ///
    /// # Errors
    /// Transport/parse errors, a non-RHC chain, missing Blue code, or zero
    /// fundable tokens.
    pub async fn verify_blue_command(rpc: &str, support: &Path) -> Result<(), String> {
        let provider = RootProvider::<Ethereum>::new_http(
            rpc.parse().map_err(|e| format!("bad rpc url: {e}"))?,
        );
        let chain = provider
            .get_chain_id()
            .await
            .map_err(|e| format!("chain-id read failed: {e}"))?;
        if chain != super::RHC_CHAIN_ID {
            return Err(format!(
                "chain id {chain} != {} (RHC) — refusing",
                super::RHC_CHAIN_ID
            ));
        }
        let code = provider
            .get_code_at(super::MORPHO_BLUE)
            .await
            .map_err(|e| format!("blue code read failed: {e}"))?;
        if code.is_empty() {
            return Err(format!(
                "morpho blue {:#?} has no code on chain {chain} — flash lender absent",
                super::MORPHO_BLUE
            ));
        }
        eprintln!("verify-blue: blue code {} bytes", code.len());
        let file =
            std::fs::File::open(support).map_err(|e| format!("support file unreadable: {e}"))?;
        let mut reader = csv::Reader::from_reader(file);
        let mut total = 0u64;
        let mut fundable = 0u64;
        for record in reader.records() {
            let record = record.map_err(|e| format!("support row unreadable: {e}"))?;
            let raw_token: Address = record
                .get(0)
                .ok_or_else(|| "support row lacks token".to_owned())?
                .parse()
                .map_err(|_| "bad token in support row".to_owned())?;
            // Same normalization as the gating path (audit A10).
            let token = crate::gaps::normalize_currency(raw_token);
            let label = record.get(1).unwrap_or("?");
            // Blue cannot lend native: only the wrapped alias can be flashed.
            let bal = if raw_token.is_zero() {
                U256::ZERO
            } else {
                super::erc20_balance_of(&provider, token, super::MORPHO_BLUE).await?
            };
            total += 1;
            if bal.is_zero() {
                println!("verify-blue: {token:#?} label={label} blue_balance=0 EMPTY");
            } else {
                fundable += 1;
                println!("verify-blue: {token:#?} label={label} blue_balance={bal} FUNDABLE");
            }
        }
        if fundable == 0 {
            return Err(format!(
                "verify-blue: 0/{total} tokens fundable — no flash capital; refusing"
            ));
        }
        println!("verify-blue: {fundable}/{total} tokens fundable");
        Ok(())
    }
}

/// The automated detect → gate → execute bridge.
pub mod trade {
    use super::{RouteRequest, Submitter};
    use alloy_primitives::{Address, Bytes, U256};
    use alloy_sol_types::SolCall;
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
            let key = cols[0]
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X")
                .to_lowercase();
            map.insert(key, (tick, hooks));
        }
        Ok(map)
    }

    /// Pre-estimate hook screen: the manifest hook policy, applied at
    /// execution time. V4 legs resolving to nonzero-hooks overrides are
    /// refused unless their pool_id is allow-listed — hook logic cannot be
    /// priced by vanilla math, and estimating such routes only burns an RPC
    /// round-trip to learn what the policy already knows (live miss: pool
    /// `85aa9a…` via hooks `0x44455203…` reverted `WrappedError` at estimate).
    ///
    /// # Errors
    /// Fails when a V4 leg is malformed or hits a non-allow-listed hook pool.
    /// Legs without overrides pass the screen (the builders fail those
    /// closed separately).
    pub fn check_v4_hook_policy(
        row: &GatedRow,
        overrides: &std::collections::HashMap<String, (i32, Address)>,
        allowlist: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        for leg in &row.legs {
            let (profile, _pool, pool_id, _tin, _tout, _fee) = parse_leg(leg)?;
            if profile != "v4" {
                continue;
            }
            let key = alloy_primitives::hex::encode(pool_id);
            if let Some((_, hooks)) = overrides.get(&key) {
                if *hooks != Address::ZERO && !allowlist.contains(&key) {
                    return Err(format!(
                        "refusing: V4 hook pool 0x{key} without allow-list (hooks {hooks:#?}; estimate would revert)"
                    ));
                }
            }
        }
        Ok(())
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
                    // V4 keys use the null sentinel for native (see denormalize_currency)
                    let tin = super::denormalize_currency(tin);
                    let tout = super::denormalize_currency(tout);
                    out.push(RouteElement::v4(tin, tout, fee_raw, *tick, *hooks));
                }
                other => return Err(format!("unknown venue profile {other:?}")),
            }
        }
        Ok(out)
    }

    /// Where trade capital comes from.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CapitalSource {
        /// Owner-seeded executor float (legacy). The executor must hold the
        /// input before every attempt.
        Float,
        /// Morpho Blue flash loan (free, per-trade). No float needed — the
        /// on-chain estimate remains the fail-closed guard.
        Morpho,
    }

    /// Parses `--capital-source` (`float` | `morpho`).
    ///
    /// # Errors
    /// Any other value (fail-closed at startup, never a silent default).
    pub fn parse_capital_source(s: &str) -> Result<CapitalSource, String> {
        match s {
            "float" => Ok(CapitalSource::Float),
            "morpho" => Ok(CapitalSource::Morpho),
            other => Err(format!(
                "unknown --capital-source {other:?} (expected float or morpho)"
            )),
        }
    }

    /// Executor entry point for one attempt. Float entries spend the
    /// owner-seeded balance on `ExecutorV3`; Morpho entries borrow from Blue
    /// on `ExecutorV4Morpho`. All four share `(token, amount, legsData,
    /// minProfit)` and the identical `RouteLeg[]` encoding.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EntryPoint {
        FloatFlash,
        FloatHybrid,
        MorphoFlash,
        MorphoHybrid,
    }

    impl EntryPoint {
        /// Picks the entry for a route: capital source × V3-leg presence.
        #[must_use]
        pub fn for_route(capital: CapitalSource, hybrid: bool) -> Self {
            match (capital, hybrid) {
                (CapitalSource::Float, false) => Self::FloatFlash,
                (CapitalSource::Float, true) => Self::FloatHybrid,
                (CapitalSource::Morpho, false) => Self::MorphoFlash,
                (CapitalSource::Morpho, true) => Self::MorphoHybrid,
            }
        }

        /// Short label for logs and estimate errors.
        #[must_use]
        pub fn describe(self) -> &'static str {
            match self {
                Self::FloatFlash => "float executeFlash",
                Self::FloatHybrid => "float executeHybrid",
                Self::MorphoFlash => "morpho executeMorphoFlash",
                Self::MorphoHybrid => "morpho executeMorphoHybrid",
            }
        }

        /// ABI-encodes the full entry call. The Morpho selectors must match
        /// `contracts/ExecutorV4Morpho.sol` (pinned by
        /// `morpho_entry_selectors` below and the forge cross-pin test).
        #[must_use]
        pub fn encode(
            self,
            token: Address,
            amount: U256,
            legs_data: &[u8],
            min_profit: U256,
        ) -> Bytes {
            let legs_data = Bytes::from(legs_data.to_vec());
            match self {
                Self::FloatFlash => super::IExecutorV3::executeFlashCall {
                    token,
                    amount,
                    legsData: legs_data,
                    minProfit: min_profit,
                }
                .abi_encode()
                .into(),
                Self::FloatHybrid => super::IExecutorV3::executeHybridCall {
                    token,
                    amount,
                    legsData: legs_data,
                    minProfit: min_profit,
                }
                .abi_encode()
                .into(),
                Self::MorphoFlash => super::IExecutorV4::executeMorphoFlashCall {
                    token,
                    amount,
                    legsData: legs_data,
                    minProfit: min_profit,
                }
                .abi_encode()
                .into(),
                Self::MorphoHybrid => super::IExecutorV4::executeMorphoHybridCall {
                    token,
                    amount,
                    legsData: legs_data,
                    minProfit: min_profit,
                }
                .abi_encode()
                .into(),
            }
        }
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
        hook_allowlist: &std::collections::HashSet<String>,
        prices: &std::collections::HashMap<Address, U256>,
        win_rate_pct: u64,
        native_usd: u64,
        gas_cap_gwei: f64,
        slippage_bps: u64,
        profit_safety_pct: u64,
        deadline_secs: u64,
        broadcast: bool,
        flash: bool,
        capital_source: CapitalSource,
    ) -> Result<TradeOutcome, String> {
        // Manifest hook policy at execution time: refuse non-allow-listed
        // hook pools before any estimate (fail-closed skip, not a revert).
        check_v4_hook_policy(row, overrides, hook_allowlist)?;
        if flash {
            // Settlement + continuity guards use the router convention:
            // native is the 0x0 sentinel, never the wrapped alias.
            let token = super::denormalize_currency(row.token_lo);
            let is_hybrid = row.legs.iter().any(|l| l.starts_with("v3:"));
            let legs_data = if is_hybrid {
                // Hybrid V3+V4 via direct leg loop in ExecutorV3: build HybridLeg[] ABI
                crate::submit::build_hybrid_legs_data(row, overrides)?
            } else {
                crate::submit::build_flash_legs_data(row, overrides)?
            };
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
            // Capital: Morpho Blue flash-funds the input per trade (no float,
            // no minimum — any gas-covered wallet can trade). The legacy
            // float mode still requires the seeded balance up front.
            if capital_source == CapitalSource::Float {
                submitter.check_executor_funded(token, row.input).await?;
            } else {
                eprintln!("preflight (flash): morpho capital — float check skipped");
            }
            // Estimate with quoted minProfit to learn gas, then enforce floor
            let entry = EntryPoint::for_route(capital_source, is_hybrid);
            eprintln!("preflight (flash): entry {}", entry.describe());
            let mut est = submitter
                .estimate_entry(entry, token, row.input, &legs_data, min_profit)
                .await?;
            eprintln!("preflight (flash): estimate {est} gas");
            // Gas floor (price table is keyed by matching-convention
            // addresses — look up the raw anchor, not the denormalized one).
            // No price → refuse (fail-closed): an unpriced input must never
            // bypass the gas_cost / win_rate floor.
            let token_usd = prices.get(&row.token_lo).copied();
            let Some(usd) = token_usd.filter(|u| !u.is_zero()) else {
                return Err(format!(
                    "refusing: input token {:#?} has no USD price — cannot size the gas floor",
                    row.token_lo
                ));
            };
            let native_usd_wei = U256::from(native_usd) * U256::from(1_000_000_000_000_000_000_u64);
            let gas_cost_usd_wei = U256::from(est) * U256::from(gas_price_wei) * native_usd_wei
                / U256::from(1_000_000_000_000_000_000_u64);
            let floor = gas_cost_usd_wei * U256::from(100_u64) / U256::from(win_rate_pct.max(1))
                * U256::from(1_000_000_000_000_000_000_u64)
                / usd;
            if floor > min_profit {
                eprintln!("trade (flash): gas floor binds {min_profit} -> {floor}");
                min_profit = floor;
                est = submitter
                    .estimate_entry(entry, token, row.input, &legs_data, min_profit)
                    .await?;
                eprintln!("preflight (flash): re-estimate {est} gas with floor");
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
                .broadcast_entry(entry, token, row.input, &legs_data, min_profit, est)
                .await?;
            return Ok(TradeOutcome {
                dry_run: false,
                detail: format!(
                    "TX {} status {} gas {}",
                    result.tx_hash, result.status, result.gas_used
                ),
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

#[cfg(test)]
mod override_key_tests {
    use super::trade::load_overrides;

    #[test]
    fn parse_capital_source_accepts_float_and_morpho_only() {
        use super::trade::{CapitalSource, parse_capital_source};
        assert_eq!(parse_capital_source("morpho"), Ok(CapitalSource::Morpho));
        assert_eq!(parse_capital_source("float"), Ok(CapitalSource::Float));
        assert!(parse_capital_source("balancer-v2").is_err());
        assert!(parse_capital_source("").is_err());
        assert!(parse_capital_source("MORPHO").is_err());
    }

    #[test]
    fn entry_point_routes_capital_times_venue() {
        use super::trade::{CapitalSource, EntryPoint};
        assert_eq!(
            EntryPoint::for_route(CapitalSource::Float, false),
            EntryPoint::FloatFlash
        );
        assert_eq!(
            EntryPoint::for_route(CapitalSource::Float, true),
            EntryPoint::FloatHybrid
        );
        assert_eq!(
            EntryPoint::for_route(CapitalSource::Morpho, false),
            EntryPoint::MorphoFlash
        );
        assert_eq!(
            EntryPoint::for_route(CapitalSource::Morpho, true),
            EntryPoint::MorphoHybrid
        );
    }

    /// Full `executeMorphoHybrid` calldata for fixed addresses, for the forge
    /// cross-pin test (`test_rust_morpho_calldata_executes`): prints
    /// `MORPHOCALLDATA_HEX`. Regenerate via
    /// `cargo test -p shadow-bot --bin shadow-bot morpho_cross_pin -- --nocapture`.
    #[test]
    fn morpho_cross_pin_emit_calldata() {
        use super::RouteLegSol;
        use super::trade::{CapitalSource, EntryPoint};
        use alloy_primitives::{Address, U256};
        use alloy_sol_types::SolValue;
        let a: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let b: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let leg = |i: Address, o: Address| RouteLegSol {
            venue: 1,
            v3Pool: Address::ZERO,
            inTok: i,
            outTok: o,
            zeroForOne: false,
            sqrtPriceLimitX96: alloy_primitives::U160::ZERO,
            fee: alloy_primitives::Uint::<24, 1>::from(0u32),
            tickSpacing: alloy_primitives::Signed::<24, 1>::try_from(200).unwrap(),
            hooks: Address::ZERO,
            hookData: alloy_primitives::Bytes::new(),
        };
        let legs = vec![leg(a, b), leg(b, a)];
        let data = EntryPoint::for_route(CapitalSource::Morpho, true).encode(
            a,
            U256::from(1_000_000_000_000_000_000_u64),
            &legs.abi_encode(),
            U256::from(1_u64),
        );
        println!(
            "MORPHOCALLDATA_HEX {}",
            alloy_primitives::hex::encode(&data)
        );
        assert_eq!(&data[..4], &[0x68, 0xb9, 0xf9, 0x38]);
    }
    /// Values derived via `cast sig` from the canonical signatures; the forge
    /// `test_entry_selectors_match_rust_submitter` test pins the other side.
    #[test]
    fn morpho_entry_selectors() {
        use super::trade::{CapitalSource, EntryPoint};
        use alloy_primitives::{Address, U256};
        let token = Address::from([0x11u8; 20]);
        let amount = U256::from(1_000_000_000_000_000_000_u64);
        let min_profit = U256::from(2000_u64);
        let legs = vec![0u8; 64];
        let flash = EntryPoint::for_route(CapitalSource::Morpho, false)
            .encode(token, amount, &legs, min_profit);
        let hybrid = EntryPoint::for_route(CapitalSource::Morpho, true)
            .encode(token, amount, &legs, min_profit);
        assert_eq!(&flash[..4], &[0x5f, 0xea, 0x06, 0xfd]); // executeMorphoFlash
        assert_eq!(&hybrid[..4], &[0x68, 0xb9, 0xf9, 0x38]); // executeMorphoHybrid
        let float_flash = EntryPoint::for_route(CapitalSource::Float, false)
            .encode(token, amount, &legs, min_profit);
        let float_hybrid = EntryPoint::for_route(CapitalSource::Float, true)
            .encode(token, amount, &legs, min_profit);
        assert_eq!(&float_flash[..4], &[0xba, 0x93, 0x20, 0x9c]); // executeFlash
        assert_eq!(&float_hybrid[..4], &[0x88, 0x89, 0x9c, 0x59]); // executeHybrid
    }

    #[test]
    fn load_overrides_normalizes_prefix_and_case() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_v4_overrides_norm.csv");
        std::fs::write(
            &path,
            "pool_id,tick_spacing,hooks\n\
             0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890,60,0x0000000000000000000000000000000000000000\n\
             0X1111111111111111111111111111111111111111111111111111111111111111,10,0x0\n",
        )
        .unwrap();
        let map = load_overrides(&path).unwrap();
        // Keys normalize to bare-lowercase so hex::encode lookups
        // (which carry no 0x prefix) must hit.
        assert!(
            map.contains_key("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        assert!(
            map.contains_key("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert!(
            !map.contains_key("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Router-leg encoding: builders emit directional in/out with the 0x0
    /// native sentinel (never sorted, never wrapped) plus override tick/hooks.
    #[test]
    fn route_legs_encode_router_convention() {
        use super::{build_flash_legs_data, trade::GatedRow};
        use alloy_primitives::{Address, Signed, U256, Uint};
        use alloy_sol_types::SolValue;

        let wrapped: Address = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73"
            .parse()
            .unwrap();
        let token: Address = "0x020bfc650a365f8BB26819deAAbF3E21291018b4"
            .parse()
            .unwrap();
        let hooks: Address = "0x37e194B1982f84e565387d28f4a7402b76b53acc"
            .parse()
            .unwrap();
        let pid = "084cee4d5edcd028175abb3a04bce5ce95b1ec2b432e6365a924c98deb78d886";
        let pm = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
        let row = GatedRow {
            kind: "pair".to_owned(),
            token_lo: wrapped,
            input: U256::from(1_000_000_u64),
            output: U256::from(1_001_000_u64),
            profit: U256::from(1_000_u64),
            legs: vec![
                format!("v4:{pm}:{pid}:{wrapped}:{token}:250"),
                format!("v4:{pm}:{pid}:{token}:{wrapped}:250"),
            ],
        };
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(pid.to_owned(), (60_i32, hooks));
        let bytes = build_flash_legs_data(&row, &overrides).unwrap();
        let legs = <Vec<super::RouteLegSol>>::abi_decode(&bytes).expect("round-trip RouteLeg[]");
        assert_eq!(legs.len(), 2);
        // Directional, denormalized: the wrapped alias never appears on the wire.
        assert_eq!(legs[0].venue, 1);
        assert_eq!(legs[0].inTok, Address::ZERO);
        assert_eq!(legs[0].outTok, token);
        assert_eq!(legs[1].inTok, token);
        assert_eq!(legs[1].outTok, Address::ZERO);
        for leg in &legs {
            assert_eq!(leg.fee, Uint::<24, 1>::from(250));
            assert_eq!(leg.tickSpacing, Signed::<24, 1>::try_from(60).unwrap());
            assert_eq!(leg.hooks, hooks);
        }
    }

    /// Hook screen: non-allow-listed nonzero-hook V4 legs are refused
    /// before any estimate (live miss: pool `85aa9a…` via hooks
    /// `0x44455203…` reverted `WrappedError` at estimate).
    #[test]
    fn hook_policy_refuses_non_allowlisted_hook_pool() {
        use super::trade::{GatedRow, check_v4_hook_policy};
        use alloy_primitives::{Address, U256};

        let pm = "0x8366a39cc670b4001a1121b8f6a443a643e40951";
        let hooked = "85aa9a7c2ef9deec7bcbc5e78c6b26d2598c2aaf3f810b267fa4f8f9b0854142";
        let plain = "7159c43bcc3961cf25e85875cbfca5eb4294fb54ce7dd88047bc3559794d832f";
        let hook_addr: Address = "0x4445520306c9c70952bdfec28f3989f53d9f80c4"
            .parse()
            .unwrap();
        let usdg: Address = "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
            .parse()
            .unwrap();
        let weth: Address = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
            .parse()
            .unwrap();
        let row = GatedRow {
            kind: "pair".to_owned(),
            token_lo: usdg,
            input: U256::from(1u64),
            output: U256::from(2u64),
            profit: U256::from(1u64),
            legs: vec![format!("v4:{pm}:{hooked}:{usdg}:{weth}:25")],
        };
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(hooked.to_owned(), (1_i32, hook_addr));
        overrides.insert(plain.to_owned(), (380_i32, Address::ZERO));

        // Empty allow-list refuses the hook pool before any estimate.
        let empty = std::collections::HashSet::new();
        let err = check_v4_hook_policy(&row, &overrides, &empty).unwrap_err();
        assert!(err.contains("without allow-list"), "unexpected: {err}");
        // Listing it permits the screen (the estimate still guards execution).
        let mut listed = std::collections::HashSet::new();
        listed.insert(hooked.to_owned());
        assert!(check_v4_hook_policy(&row, &overrides, &listed).is_ok());
        // Zero-hook legs always pass the screen.
        let clean = GatedRow {
            legs: vec![format!("v4:{pm}:{plain}:{usdg}:{weth}:38000")],
            ..row
        };
        assert!(check_v4_hook_policy(&clean, &overrides, &empty).is_ok());
    }
}
