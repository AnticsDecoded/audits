## About Antics

I'm an independent Web3 Security Researcher competing on Immunefi, Cantina, Sherlock, C4, and Codehawks. Skilled in Rust, Go, Solidity, and C++, I specialize in identifying vulnerabilities in blockchain protocols — L1 daemons, wallets, and on-chain contracts.

For collabs or security audits, reach out on X [@AnticsDecoded](https://x.com/AnticsDecoded).

## Bug Bounties

### Immunefi

| Program | Category | Language | Findings | Report |
| ------- | -------- | -------- | -------- | ------ |
| [Zano](https://github.com/hyle-team/zano) | Privacy L1 (CryptoNote / Zarcanum) | C++ | 1 Critical · 1 High · 2 Low | [source](reports/Zano.md) |
| [monero-oxide](https://github.com/monero-oxide/monero-oxide) | Privacy Wallet / Ring Signatures | Rust | 1 Medium | [source](reports/monero-oxide.md) |
| [Utix](https://etherscan.io/address/0xc9d7bd1Fad7D5621DdA20335818E9575Ae07Ea03) | Token Crowdsale | Solidity | 1 Critical | [source](reports/Utix.md) |

## Findings by severity

| Severity | Finding | Program |
| -------- | ------- | ------- |
| Critical | EOA-only withdrawal guard permanently locks 451 ETH | [Utix](reports/Utix.md) |
| Critical | Unauthenticated `reset_transaction_pool` admin RPC purges the mempool | [Zano](reports/Zano.md) |
| High | Unbounded transaction acceptance in `tx_pool` enables resource-exhaustion DoS | [Zano](reports/Zano.md) |
| Medium | Off-by-one in decoy selection excludes the real output from the first RPC batch | [monero-oxide](reports/monero-oxide.md) |
| Low | Wallet↔daemon HTTPS connection performs no TLS certificate validation | [Zano](reports/Zano.md) |
| Low | JWT anti-replay salts are not persisted, enabling RPC command replay across restart | [Zano](reports/Zano.md) |

Each report contains the finding's description and impact, the vulnerable code, a runnable
proof-of-concept (linked under [`reports/poc/`](reports/poc/)), and recommended mitigation steps.
