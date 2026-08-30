//! Live probe: dump recent router `0x4d819a2a` calldata for offline decode.
//! Read-only; ignored by default (`cargo test -p simulation --ignored dump_router_calldata`).

#![allow(
    clippy::too_many_lines,
    unused_imports,
    clippy::default_trait_access,
    clippy::useless_format,
    clippy::doc_markdown,
    clippy::match_same_arms
)]

use revm::context_interface::journaled_state::JournalTr as _;
use revm::context_interface::local::LocalContextTr as _;

#[test]
#[ignore = "live: needs the RHC gateway; run with --ignored"]
fn dump_router_calldata() {
    use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};

    let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
    let reader = ChainReader::new(
        LiveHttp::new(rpc.parse().unwrap()),
        ThreadSleeper,
        ProviderBudget::new(200_000, 1 << 24),
        RetryPolicy {
            max_retries: 6,
            initial_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
        },
        4663,
    );
    reader.validate_chain_id().unwrap();

    let router: alloy_primitives::Address = "0x65050a9b7e5075a2ba5ced7b1b64ee66262c40dc"
        .parse()
        .unwrap();
    let head = reader.current_block().expect("head");

    let mut dumped = 0usize;
    let mut seen: Vec<String> = Vec::new();
    // Walk back in chunks; the gateway serves only ~1-2 min of history.
    for back in [8u64, 40, 120, 400] {
        if dumped >= 5 {
            break;
        }
        let from = head.saturating_sub(back);
        // Scan the whole block range for txs to the router via logs from any
        // PM swap activity, then pull the txs and filter calldata.
        let pm: alloy_primitives::Address = "0x8366a39CC670B4001A1121B8F6A443A643e40951"
            .parse()
            .unwrap();
        let swap_topic: alloy_primitives::B256 =
            "0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f"
                .parse()
                .unwrap();
        let logs = reader
            .get_logs(&provider::LogFilter {
                from_block: from,
                to_block: head,
                addresses: vec![pm],
                topic0: swap_topic,
                topic0_alternates: Vec::new(),
            })
            .unwrap_or_default();
        for l in logs.iter().rev() {
            if dumped >= 5 {
                break;
            }
            let Some(txh) = l["transactionHash"].as_str() else {
                continue;
            };
            if seen.iter().any(|s| s == txh) {
                continue;
            }
            let Ok(Some(t)) = reader.transaction_by_hash(txh) else {
                continue;
            };
            let to_ok = t["to"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(&format!("{router:?}")));
            let Some(input) = t["input"].as_str() else {
                continue;
            };
            if !to_ok || !input.starts_with("0x4d819a2a") {
                continue;
            }
            seen.push(txh.to_owned());
            let value = t["value"].as_str().unwrap_or("0x0");
            let blk = t["blockNumber"].as_str().unwrap_or("0x0");
            println!(
                "=== tx {txh} block {blk} value {value} input_len {} ===",
                input.len() / 2 - 1
            );
            println!("{}", &input[2..]);
            dumped += 1;
        }
    }
    println!("dumped {dumped} router txs");
    assert!(dumped > 0, "no router txs found in the recent horizon");
}

/// Discover `tickSpacing`/`hooks` for target V4 pools from live `Initialize`
/// events (the enumeration CSV omits them — audit B58). Read-only.
#[test]
#[ignore = "live: needs the RHC gateway; run with --ignored"]
fn discover_v4_pool_params() {
    use provider::{ChainReader, LiveHttp, LogFilter, ProviderBudget, RetryPolicy, ThreadSleeper};
    use std::collections::HashMap;

    let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
    let reader = ChainReader::new(
        LiveHttp::new(rpc.parse().unwrap()),
        ThreadSleeper,
        ProviderBudget::new(400_000, 1 << 24),
        RetryPolicy {
            max_retries: 6,
            initial_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
        },
        4663,
    );
    reader.validate_chain_id().unwrap();
    let pm = crate::executor::pool_manager_address();
    let head = reader.current_block().expect("head");

    // Targets: the two distinct native/0x1462 V4 pools (fee 30000, 29000)
    // plus the hot dynamic-fee pool for reference.
    let targets: Vec<(&str, &str)> = vec![
        (
            "0xa90ab594406b98c923e8d72a1212f0fabcf5f51ba2f1a4687a149fee0e3cc395",
            "fee30000",
        ),
        (
            "0xbb16e744322e0e548896b5185a656226251b2bcc5a20252898c1e8142f045d15",
            "fee29000",
        ),
        (
            "0xb0e295a19977ec1900bb73aee30a8a44ed49f20ca2a7215a2c8634961f89f972",
            "fee999243",
        ),
        (
            "0x7848f09faf2b601f8d14b8ba3ef085b2d1708c7915ec052178f89ecb716e872a",
            "fee850000",
        ),
        (
            "0x67f42211983a4a5a1d40501f9fb18305002d932c84dba080b0b5f6e9b5d3d29a",
            "fee500000",
        ),
        (
            "0x23bcbfac2340000000000000000000000000000000000000000000000000000",
            "hot-dynamic",
        ),
    ];
    let want: HashMap<String, &str> = targets
        .iter()
        .map(|(id, n)| (id.to_lowercase(), *n))
        .collect();

    let mut found: HashMap<String, String> = HashMap::new();
    // Chunked sweep: 5k-block windows, up to 300k blocks back. The gateway
    // rate-limits big ranges; small windows keep each call fast.
    let mut latest_block: u64 = head;
    'outer: for chunk_start in (head.saturating_sub(60_000)..head).step_by(600) {
        let from = chunk_start;
        let to = (chunk_start + 600).min(head);
        latest_block = to;
        eprintln!("window {from}-{to}");
        let logs = match reader.get_logs(&LogFilter {
            from_block: from,
            to_block: to,
            addresses: vec![pm],
            topic0: provider::v4_initialize_topic(),
            topic0_alternates: Vec::new(),
        }) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("getLogs {from}-{to} failed: {e}");
                continue;
            }
        };
        for l in &logs {
            let topics: Vec<alloy_primitives::B256> = l["topics"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().and_then(|s| s.parse().ok()))
                        .collect()
                })
                .unwrap_or_default();
            let data: alloy_primitives::Bytes = l["data"]
                .as_str()
                .unwrap_or("0x")
                .parse()
                .unwrap_or_default();
            let env = provider::RawLogEnvelope {
                address: pm,
                topics,
                data,
                block_number: 0,
                transaction_index: 0,
                log_index: 0,
                removed: false,
                block_hash: Default::default(),
            };
            if let Some(init) = provider::decode_v4_initialize(&env) {
                let id = alloy_primitives::hex::encode(init.id);
                if want.contains_key(&id) && !found.contains_key(&id) {
                    found.insert(
                        id.clone(),
                        format!(
                            "fee={} tickSpacing={} hooks={:#?}",
                            init.fee, init.tick_spacing, init.hooks
                        ),
                    );
                    eprintln!("found {id} at block {to}");
                    if found.len() >= targets.len() {
                        break 'outer;
                    }
                }
            }
        }
    }
    eprintln!("swept up to block {latest_block}");
    for (id, name) in &want {
        match found.get(&format!("{id}")) {
            Some(params) => println!("DISCOVERED {name} {id}: {params}"),
            None => println!("MISSING    {name} {id} (no Initialize in horizon)"),
        }
    }
}

/// Replay a CLOSED native cycle on a live fork through ExecutorV2:
/// `execute{value}` -> [V3 WETH->T (router wraps the native input), V4 T->native].
/// Every building block is live-proven (wrap-in: tx2, V3->V4 handoff: tx2,
/// native-out: tx0); only the target V4 pool's components are guessed, so the
/// test sweeps a small component grid and reports which resolve.
#[test]
#[ignore = "live: needs the RHC gateway; run with --ignored"]
fn executor_v2_replay() {
    use crate::payload_builder::{RouteElement, VENUE_V3, VENUE_V4, encode_swap_calldata};
    use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
    use revm::context::TxEnv;
    use revm::database::CacheDB;
    use revm::handler::{ExecuteCommitEvm, MainBuilder};
    use revm::primitives::hardfork::SpecId;

    let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
    let reader = ChainReader::new(
        LiveHttp::new(rpc.parse().unwrap()),
        provider::ThreadSleeper,
        ProviderBudget::new(600_000, 1 << 24),
        RetryPolicy {
            max_retries: 6,
            initial_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
        },
        4663,
    );
    reader.validate_chain_id().unwrap();

    let _executor_unused: alloy_primitives::Address = "0x5d1Aa3f67AC0Ee82FB46497deE85105C070AE93B"
        .parse()
        .unwrap();
    let owner: alloy_primitives::Address = "0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
        .parse()
        .unwrap();
    let weth: alloy_primitives::Address = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
        .parse()
        .unwrap();
    let t: alloy_primitives::Address = "0x14623dD0784cb5C484F8935c7c218d110332b538"
        .parse()
        .unwrap();
    let v3_pool: alloy_primitives::Address = "0x03cC14c8Bc55a487DA89847A432E4220f46dFC63"
        .parse()
        .unwrap();
    let pm = crate::executor::pool_manager_address();

    // Leg 0: WETH -> T via the activity-manifest V3 pool (fee 10000 -> tick 200).
    let leg0 = RouteElement {
        venue_type: VENUE_V3,
        currency0: weth,
        currency1: t,
        pool: v3_pool,
        fee: 10_000, // pool's immutable fee() = 0x2710 on-chain; CSV row was wrong
        tick_spacing: 200,
        hooks: alloy_primitives::Address::ZERO,
        pool_manager: alloy_primitives::Address::ZERO,
        pool_key: [0u8; 32],
        hook_data: Vec::new(),
    };
    // Leg 1 guesses: the CSV lists two distinct native/T V4 pools (fee 30000,
    // 29000); tickSpacing and hooks are not in the CSV, so sweep a small grid.
    let fees = [30_000u32, 29_000];
    let ticks = [8i32, 60];
    let hooks = [
        alloy_primitives::Address::ZERO,
        "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
            .parse()
            .unwrap(),
    ];
    let amount = alloy_primitives::U256::from(20_000_000_000_000_000_u64); // 0.02 native

    for fee in fees {
        for tick in ticks {
            for hook in hooks {
                let leg1 = RouteElement {
                    venue_type: VENUE_V4,
                    currency0: t,
                    currency1: alloy_primitives::Address::ZERO,
                    pool: alloy_primitives::Address::ZERO,
                    fee,
                    tick_spacing: tick,
                    hooks: hook,
                    pool_manager: pm,
                    pool_key: [0u8; 32],
                    hook_data: Vec::new(),
                };
                let elements = [leg0.clone(), leg1];
                let Ok(router_data) = encode_swap_calldata(
                    &elements,
                    amount,
                    alloy_primitives::U256::ZERO,
                    alloy_primitives::U256::from(1_900_000_000_u64),
                ) else {
                    continue;
                };
                // Direct router call (skip executor) to surface raw revert reasons.
                let data = router_data.clone();

                let head = reader.current_block().expect("head");
                let mut db = CacheDB::new(crate::fork::ForkDb::new(
                    ChainReader::new(
                        LiveHttp::new(rpc.parse().unwrap()),
                        provider::ThreadSleeper,
                        ProviderBudget::new(600_000, 1 << 24),
                        RetryPolicy {
                            max_retries: 6,
                            initial_delay: std::time::Duration::from_secs(2),
                            max_delay: std::time::Duration::from_secs(30),
                        },
                        4663,
                    ),
                    head,
                ));
                db.insert_account_info(
                    owner,
                    revm::state::AccountInfo {
                        balance: alloy_primitives::U256::from(1_000_000_000_000_000_000_u128),
                        ..revm::state::AccountInfo::default()
                    },
                );
                let router_addr: alloy_primitives::Address =
                    "0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc"
                        .parse()
                        .unwrap();
                let tx = TxEnv::builder()
                    .caller(owner)
                    .kind(alloy_primitives::TxKind::Call(router_addr))
                    .value(amount)
                    .data(alloy_primitives::Bytes::from(data))
                    .gas_limit(3_000_000)
                    .build()
                    .unwrap();
                let mut evm = <crate::engine::SimContext<
                    CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
                >>::new(db, SpecId::PRAGUE)
                .modify_cfg_chained(|cfg| {
                    cfg.disable_nonce_check = true;
                    cfg.disable_eip3607 = true;
                })
                .build_mainnet();
                let res = evm.transact_commit(tx).unwrap();
                let gas = match &res {
                    revm::context::result::ExecutionResult::Success { gas, .. } => {
                        gas.total_gas_spent()
                    }
                    revm::context::result::ExecutionResult::Revert { gas, .. } => {
                        gas.total_gas_spent()
                    }
                    revm::context::result::ExecutionResult::Halt { gas, .. } => {
                        gas.total_gas_spent()
                    }
                };
                let reason = if res.is_success() {
                    "SUCCESS"
                } else {
                    "revert "
                };
                println!(
                    "fee={fee} tick={tick} hooks={hook:#?} -> {reason} gas={gas} out={}",
                    res.output()
                        .cloned()
                        .map(|o| alloy_primitives::hex::encode(o.as_ref()))
                        .unwrap_or_default()
                );
            }
        }
    }
}

/// Records every CALL made during the router swap to expose the PoolManager's
/// real function ABI (the fork's dispatch is via-IR — no PUSH4 immediates).
#[derive(Default)]
pub struct CallTreeInspector {
    pub calls: Vec<(usize, String, String, u128)>,
    pub pm_inputs: Vec<(String, String)>,
}

impl<CTX, INTR> revm::inspector::Inspector<CTX, INTR> for CallTreeInspector
where
    CTX: revm::context_interface::ContextTr,
    INTR: revm::interpreter::InterpreterTypes,
{
    fn call(
        &mut self,
        context: &mut CTX,
        inputs: &mut revm::interpreter::CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        let depth = context.journal().depth();
        let target = inputs.target_address;
        let value = inputs.value.clone().get().to::<u128>();
        let input: Vec<u8> = match &inputs.input {
            revm::interpreter::CallInput::Bytes(bytes) => bytes.to_vec(),
            revm::interpreter::CallInput::SharedBuffer(range) => context
                .local()
                .shared_memory_buffer_slice(range.clone())
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        };
        let selector = if input.len() >= 4 {
            alloy_primitives::hex::encode(&input[..4])
        } else {
            format!("len{}", input.len())
        };
        self.calls
            .push((depth, format!("{target:#?}"), selector.clone(), value));
        let pm_target = alloy_primitives::Address::new([
            0x83, 0x66, 0xa3, 0x9c, 0xc6, 0x70, 0xb4, 0x00, 0x1a, 0x11, 0x21, 0xb8, 0xf6, 0xa4,
            0x43, 0xa6, 0x43, 0xe4, 0x09, 0x51,
        ]);
        if target == pm_target {
            self.pm_inputs.push((
                selector.clone(),
                alloy_primitives::hex::encode(&input[4..input.len().min(4 + 320)]),
            ));
        }
        None
    }
}

/// Simulate the 1-leg router swap through ExecutorV2 and dump the sub-call
/// tree: this IS the live PM ABI (unlock/take/settle/swap selectors).
#[test]
#[ignore = "live: needs the RHC gateway; run with --ignored"]
fn router_subcall_tree() {
    use crate::payload_builder::{RouteElement, V4_DYNAMIC_FEE_SENTINEL, encode_swap_calldata};
    use provider::{ChainReader, LiveHttp, ProviderBudget, RetryPolicy, ThreadSleeper};
    use revm::context::TxEnv;
    use revm::database::CacheDB;
    use revm::handler::MainBuilder;
    use revm::inspector::InspectEvm;
    use revm::primitives::hardfork::SpecId;

    let rpc = std::env::var("ROBINHOOD_HTTP_RPC_URL")
        .unwrap_or_else(|_| "https://rpc.mainnet.chain.robinhood.com".to_owned());
    let reader = ChainReader::new(
        LiveHttp::new(rpc.parse().unwrap()),
        provider::ThreadSleeper,
        ProviderBudget::new(400_000, 1 << 24),
        RetryPolicy {
            max_retries: 6,
            initial_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
        },
        4663,
    );
    reader.validate_chain_id().unwrap();

    let executor: alloy_primitives::Address = "0x5d1Aa3f67AC0Ee82FB46497deE85105C070AE93B"
        .parse()
        .unwrap();
    let owner: alloy_primitives::Address = "0x3219E15A8d1e82368340dfB6697fE6a6B41d686D"
        .parse()
        .unwrap();
    let token: alloy_primitives::Address = "0xccf14ec1f58b04baa52ce0c562899c26db7d1e18"
        .parse()
        .unwrap();
    let hook: alloy_primitives::Address = "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
        .parse()
        .unwrap();
    let router: alloy_primitives::Address = "0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc"
        .parse()
        .unwrap();
    let pm: alloy_primitives::Address = "0x8366a39CC670B4001A1121B8F6A443A643e40951"
        .parse()
        .unwrap();

    let elements = [RouteElement::v4(
        alloy_primitives::Address::ZERO,
        token,
        V4_DYNAMIC_FEE_SENTINEL,
        8,
        hook,
    )];
    let amount = alloy_primitives::U256::from(20_000_000_000_000_000_u64);
    let router_data = encode_swap_calldata(
        &elements,
        amount,
        alloy_primitives::U256::ZERO,
        alloy_primitives::U256::from(1_900_000_000_u64),
    )
    .unwrap();

    let mut data = Vec::new();
    data.extend_from_slice(
        &alloy_primitives::keccak256("execute(address,uint256,bytes,uint256)")[0..4],
    );
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    data.extend_from_slice(&alloy_primitives::U256::from(0x80u32).to_be_bytes::<32>());
    data.extend_from_slice(&alloy_primitives::U256::ZERO.to_be_bytes::<32>());
    data.extend_from_slice(&alloy_primitives::U256::from(router_data.len()).to_be_bytes::<32>());
    data.extend_from_slice(&router_data);

    let head = reader.current_block().expect("head");
    let mut db = CacheDB::new(crate::fork::ForkDb::new(reader, head));
    db.insert_account_info(
        owner,
        revm::state::AccountInfo {
            balance: alloy_primitives::U256::from(1_000_000_000_000_000_000_u128),
            ..revm::state::AccountInfo::default()
        },
    );
    let tx = TxEnv::builder()
        .caller(owner)
        .kind(alloy_primitives::TxKind::Call(executor))
        .value(amount)
        .data(alloy_primitives::Bytes::from(data))
        .gas_limit(3_000_000)
        .build()
        .unwrap();
    let inspector = CallTreeInspector::default();
    let mut evm = <crate::engine::SimContext<
        CacheDB<crate::fork::ForkDb<provider::LiveHttp, provider::ThreadSleeper>>,
    >>::new(db, SpecId::PRAGUE)
    .modify_cfg_chained(|cfg| {
        cfg.disable_nonce_check = true;
        cfg.disable_eip3607 = true;
    })
    .build_mainnet_with_inspector(inspector);
    let res = evm.inspect_one_tx(tx).unwrap();
    println!(
        "result: {}",
        if res.is_success() {
            "SUCCESS"
        } else {
            "REVERT"
        }
    );
    println!("sub-call tree (depth, target, selector, value):");
    for (depth, target, sel, value) in &evm.inspector.calls {
        let label = if *target == format!("{pm:#?}") {
            "PM"
        } else if *target == format!("{router:#?}") {
            "ROUTER"
        } else if *target == format!("{hook:#?}") {
            "HOOK"
        } else {
            ""
        };
        println!("  d{depth} {label:6} {target} sel=0x{sel} value={value}");
    }
}

/// Print fresh router calldata for the 1-leg native route (for fork tests).
#[test]
#[ignore = "live: prints fresh calldata; run with --ignored"]
fn print_fresh_router_calldata() {
    use crate::payload_builder::{RouteElement, V4_DYNAMIC_FEE_SENTINEL, encode_swap_calldata};
    let elements = [RouteElement::v4(
        alloy_primitives::Address::ZERO,
        "0xccf14ec1f58b04baa52ce0c562899c26db7d1e18"
            .parse()
            .unwrap(),
        V4_DYNAMIC_FEE_SENTINEL,
        8,
        "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"
            .parse()
            .unwrap(),
    )];
    let deadline: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let cd = encode_swap_calldata(
        &elements,
        alloy_primitives::U256::from(20_000_000_000_000_000_u64),
        alloy_primitives::U256::ZERO,
        alloy_primitives::U256::from(deadline),
    )
    .unwrap();
    println!("FRESH_CALLDATA={}", alloy_primitives::hex::encode(&cd));
}
