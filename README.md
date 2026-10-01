# Robinhood Chain arbitrage bot

Multi-hop cyclic arbitrage on **Robinhood Chain (RHC, chain 4663)**. Rust hot
path, Solidity executor, and in-process `revm` simulation before any
broadcast.

## How it works

- **Local pool state.** Reserves are fetched once at startup and then kept
  current from `Sync`/`Swap` events over WebSocket. Pricing math runs
  in-process — there is no RPC call per quote.
- **Precomputed cycles.** Routes are compiled offline from a pool manifest and
  indexed by pool. An event re-checks only the cycles touching the pool that
  changed, never the full graph.
- **Closed-form optimal input** for V2-style paths — no search over trade
  sizes.
- **Simulate, then broadcast.** Each candidate executes under `revm` first,
  which doubles as the honeypot filter: fee-on-transfer and
  revert-on-transfer tokens fail locally instead of on-chain.
- **Coverage over latency.** Racing colocated builders on speed is unwinnable
  at this scale, so the edge comes from pool coverage — new pools,
  fee-on-transfer tokens, unusual curves, low-TVL forks.

Detection and submission are separate loops: `run-pairs` evaluates a hot
manifest and appends gated opportunities to a CSV; `trade` tails that CSV and
submits only when `--broadcast` is passed.

## Layout

| Path | Contents |
|---|---|
| `crates/domain` | chain ids, config, shared types |
| `crates/v2-math` | quoting and closed-form optimal input |
| `crates/catalog` | manifest parsing, cycle compilation |
| `crates/state` | local reserve store, reorg handling |
| `crates/provider` | HTTP and WebSocket RPC lanes, event ingestion |
| `crates/storage` | SQLite persistence |
| `crates/simulation` | `revm` executor and payload builder |
| `crates/shadow` | evaluation service |
| `crates/shadow-bot` | CLI |
| `contracts/` | executor contracts (Foundry) |
| `data/` | pool manifests, overrides, price tables |
| `scripts/` | operational helpers |

## Prerequisites

- Rust (pinned by `rust-toolchain.toml`)
- Foundry (`forge`) for the contracts
- Node.js for the OpenZeppelin remappings

## Setup

```bash
npm install
forge build
cargo build --release
cargo test
```

Copy `.env.example` and export the listed variables in the shell that runs the
bot. Values stay in your environment — never in this repository. See
`SECURITY.md`.

Runtime configuration is generated once from `config/shadow.example.toml` into
the gitignored `config/shadow.toml`.

Large pool catalogs are regenerable and are not committed; the small tracked
manifests in `data/` are enough to build and test.

## Commands

Offline and read-only:

```bash
cargo run -p shadow-bot -- validate-config --config config/shadow.toml
cargo run -p shadow-bot -- verify-catalog --manifest data/pools.example.csv
cargo run -p shadow-bot -- run --config config/shadow.toml \
    --snapshot tests/fixtures/service/snapshot.json --db shadow.sqlite
cargo run -p shadow-bot -- replay-observation 1 --db shadow.sqlite
cargo run -p shadow-bot -- daily-report --db shadow.sqlite --date 2026-08-05
```

Detection and submission:

```bash
./scripts/run-shadow.sh --validate-config --config config/shadow.toml
./scripts/launch-hot.sh        # hot-manifest detection loop
./scripts/launch-live.sh       # trade loop (dry-run unless --broadcast)
./scripts/check-secrets.sh     # run before every commit
```

`trade` and `submit-exec` preflight and simulate first, and only sign when
`--broadcast` is passed. Every submission must clear the gate documented in
`SECURITY.md`.

## Tests

```bash
cargo test
forge test --summary
```

## Security

Operating constraints — secret handling, RPC discipline, the submission gate,
and the deployment checklist — are in `SECURITY.md`. Read it before running
anything that can broadcast.
