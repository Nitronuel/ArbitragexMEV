# Security and operating constraints

These rules are load-bearing. Several exist to keep the bot inside a fixed
lifetime attempt budget; violating one does not cause a test failure, it
burns money silently.

## Secrets

- Private keys and provider credentials come from the runtime environment
  only. They are never written to a file in this repository, never passed as
  a CLI argument, and never printed to a log or a process argument list.
- `.env` and `config/shadow.toml` are gitignored operator files.
  `.env.example` lists variable *names* with empty values.
- `scripts/check-secrets.sh` scans tracked and staged content for
  credential-shaped assignments, API-key URL paths, JWTs and `sk-` tokens.
  Run it before every commit. Bare `0x` + 64-hex is warning-only outside
  `data/` because a raw key is shape-identical to a keccak hash and the pool
  catalogs legitimately contain tens of thousands of them.
- Keys in shell history or `~/.bashrc` are the operator's responsibility;
  keep that file mode 600.

## RPC discipline

- **Never `eth_call` per quote.** Every quote is priced in-process against
  locally cached pool state. Continuous `eth_call` pricing blows the provider
  quota in hours and is the constraint the entire architecture is built
  around.
- Provider endpoints are split: the free public gateway carries continuous
  polling, archive-depth reads go to a dedicated provider. Don't invert the
  split.

## Submission gate

Broadcast only when

```
simulated_profit > gas_cost / expected_win_rate
```

At a 10% win rate and $0.03 gas the floor is ~$0.30. Submitting below the
floor is how the gas budget dies in a week with nothing learned. Detection
vs. won opportunities are logged continuously; capture rate
(`won / detected`) is the primary health metric.

Every submission is simulated in-process with `revm` before broadcast. That
simulation doubles as the honeypot filter: fee-on-transfer and
revert-on-transfer tokens fail there instead of on-chain.

## Deployment

- Run the project deployment/verification checklist before any mainnet
  deployment or upgrade of the executor — it moves borrowed funds.
- The executor holds no inventory: capital is always flash-borrowed and
  repaid inside the same transaction, with `minProfit` enforced on-chain.
- Budget the wallet as a finite attempt counter, not a balance. Reverts cost
  gas too.

## Scope

No frontrunning, no mempool, no MEV-Boost, no relays, no bundle market.
Every strategy here is a backrun of confirmed or preconfirmed state.
