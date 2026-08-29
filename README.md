# About Antics
I'm an independent Security Researcher competing on Immunefi, Cantina, Sherlock, C4, and Codehawks. Skilled in Rust, Go, Solidity, and C++, I specialize in identifying vulnerabilities in blockchain protocols.

For collabs or security audits, reach out on X [@AnticsDecoded](https://x.com/AnticsDecoded)

---

# Security Findings Portfolio

A curated set of **submitted and outcome-verified** blockchain, wallet, and smart-contract
findings hunted on **[Immunefi](https://bugs.immunefi.com/)**. Every entry was submitted to a
live program, carries a **runnable proof-of-concept**, and reached a favorable terminal outcome:
it was **rewarded**, or **closed as a duplicate / already-known issue** (the bug was real and
accepted — a prior report just claimed the reward first). Reports rejected on the merits are
excluded.

**3 Rewarded · 3 Duplicate/Known** — drawn from 37 Immunefi submissions across 20+ programs.
Full index and exclusions in **[PORTFOLIO.md](./PORTFOLIO.md)**. Each finding lives in
[`findings/<severity>/<nn>-<slug>/`](findings/) with a `README.md`, a full `REPORT.md`, the
original `ISSUE-1.md` submission, and PoC file(s).

## Rewarded

| # | Target | Finding | Final Severity | Reward |
|---|--------|---------|----------------|--------|
| 04 | monero-oxide (`wallet/src/decoys.rs`) | Off-by-one in decoy selection excludes the real output from the first RPC batch → true-spend fingerprint | Medium | **$2,500 (XMR)** |
| 05 | Zano (`core_default_rpc_proxy.cpp`) | Wallet↔daemon HTTPS connection skips TLS certificate validation → MITM over RPC | Low | **$1,000 (USDC)** |
| 06 | Zano (`wallet_rpc_server.cpp`) | JWT anti-replay salts held in-memory only → signed RPC commands replayable across restart | Low | **$1,000 (USDC)** |

## Duplicate / already-known (accepted as real, prior report claimed the reward)

| # | Target | Finding | Severity | Status |
|---|--------|---------|----------|--------|
| 01 | Utix (`MintedTokenCappedCrowdsaleExtv1`, mainnet) | `extcodesize==0` withdrawal guard rejects the Gnosis-Safe multisig → 451 ETH permanently locked | Critical | Duplicate of #22566 (Immunefi-verified) |
| 02 | Zano (`core_rpc_server.cpp`) | `reset_transaction_pool` admin RPC purges the mempool with no auth | Critical | Duplicate of #49357 |
| 03 | Zano (`tx_pool.cpp`) | No early size/input/output/proof-complexity bound on accepted txs → resource-exhaustion DoS | High | Acknowledged known issue |

See **[PORTFOLIO.md](./PORTFOLIO.md)** for per-finding notes, the "what verified means" bar, and
the full list of submissions excluded because a program rejected them on the merits.
