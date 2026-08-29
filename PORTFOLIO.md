# Security Findings Portfolio — @AnticsDecoded

A curated set of blockchain, wallet, and smart-contract security findings. Every entry carries a
full technical write-up and a **runnable proof-of-concept**, spanning Rust, Go, Solidity, and C++
codebases across L1 daemons, wallets, and on-chain contracts.

Each finding lives in [`findings/<severity>/<nn>-<slug>/`](findings/) with a `README.md` index, a
full `REPORT.md`, the finding submission text (`ISSUE-1.md`), and the PoC file(s).

---

## Critical

| # | Target | Finding | Folder |
|---|--------|---------|--------|
| 01 | Utix — `MintedTokenCappedCrowdsaleExtv1` (mainnet) | `extcodesize==0` withdrawal guard rejects the Gnosis-Safe multisig → 451 ETH permanently locked | [`01-utix-eoa-only-withdrawal-guard-451eth-lock`](findings/critical/01-utix-eoa-only-withdrawal-guard-451eth-lock/) |
| 02 | Zano — `core_rpc_server.cpp` | `reset_transaction_pool` admin RPC purges the mempool with no authentication | [`02-zano-unauth-admin-rpc-mempool-purge`](findings/critical/02-zano-unauth-admin-rpc-mempool-purge/) |

## High

| # | Target | Finding | Folder |
|---|--------|---------|--------|
| 03 | Zano — `tx_pool.cpp` | No early size/input/output/proof-complexity bound on accepted txs → resource-exhaustion DoS | [`03-zano-txpool-unbounded-tx-resource-exhaustion`](findings/high/03-zano-txpool-unbounded-tx-resource-exhaustion/) |

## Medium

| # | Target | Finding | Folder |
|---|--------|---------|--------|
| 04 | monero-oxide — `wallet/src/decoys.rs` | Off-by-one in decoy selection excludes the real output from the first RPC batch → true-spend fingerprint | [`04-monero-oxide-decoy-offbyone-true-spend-fingerprint`](findings/medium/04-monero-oxide-decoy-offbyone-true-spend-fingerprint/) |

## Low

| # | Target | Finding | Folder |
|---|--------|---------|--------|
| 05 | Zano — `core_default_rpc_proxy.cpp` | Wallet↔daemon HTTPS connection skips TLS certificate validation → MITM over RPC | [`05-zano-daemon-rpc-missing-tls-validation-mitm`](findings/low/05-zano-daemon-rpc-missing-tls-validation-mitm/) |
| 06 | Zano — `wallet_rpc_server.cpp` | JWT anti-replay salts held in-memory only → signed RPC commands replayable across restart | [`06-zano-jwt-salt-not-persisted-rpc-replay`](findings/low/06-zano-jwt-salt-not-persisted-rpc-replay/) |

---

## What each finding includes

1. **A concrete root cause** — the exact code and the invariant it breaks.
2. **A runnable PoC** — a test, script, or exact command sequence that demonstrates the issue.
3. **Remediation** — the fix, described precisely.
