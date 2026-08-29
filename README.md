# About Antics
I'm an independent Security Researcher competing on Immunefi, Cantina, Sherlock, C4, and Codehawks. Skilled in Rust, Go, Solidity, and C++, I specialize in identifying vulnerabilities in blockchain protocols.

For collabs or security audits, reach out on X [@AnticsDecoded](https://x.com/AnticsDecoded)

---

# Security Findings Portfolio

A curated set of blockchain, wallet, and smart-contract security findings, each with a full
technical write-up and a **runnable proof-of-concept**. Findings span Rust, Go, Solidity, and
C++ codebases across L1 daemons, wallets, and on-chain contracts.

Full index in **[PORTFOLIO.md](./PORTFOLIO.md)**. Each finding lives in
[`findings/<severity>/<nn>-<slug>/`](findings/) with a `README.md`, a full `REPORT.md`, the
finding submission text (`ISSUE-1.md`), and PoC file(s).

## Findings

| # | Target | Finding | Severity |
|---|--------|---------|----------|
| 01 | Utix — `MintedTokenCappedCrowdsaleExtv1` (Ethereum mainnet) | `extcodesize==0` withdrawal guard rejects the Gnosis-Safe multisig → 451 ETH permanently locked | Critical |
| 02 | Zano — `core_rpc_server.cpp` | `reset_transaction_pool` admin RPC purges the mempool with no authentication | Critical |
| 03 | Zano — `tx_pool.cpp` | No early size/input/output/proof-complexity bound on accepted txs → resource-exhaustion DoS | High |
| 04 | monero-oxide — `wallet/src/decoys.rs` | Off-by-one in decoy selection excludes the real output from the first RPC batch → true-spend fingerprint | Medium |
| 05 | Zano — `core_default_rpc_proxy.cpp` | Wallet↔daemon HTTPS connection skips TLS certificate validation → MITM over RPC | Low |
| 06 | Zano — `wallet_rpc_server.cpp` | JWT anti-replay salts held in-memory only → signed RPC commands replayable across restart | Low |
