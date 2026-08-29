# Security Findings Portfolio — @AnticsDecoded

A curated set of **submitted and outcome-verified** blockchain, wallet, and smart-contract
security findings, hunted on **[Immunefi](https://bugs.immunefi.com/)**. Every entry below
was submitted to a live bug-bounty program, carries a **runnable proof-of-concept**, and
reached one of two terminal outcomes: it was **rewarded** by the project, or it was **closed
as a duplicate / already-known issue** — i.e. the bug was real and accepted, but a prior
report claimed the reward first.

Findings that programs closed as **invalid, out-of-scope, or low-quality on the merits** are
deliberately **excluded** — see [Deliberately excluded](#deliberately-excluded).

**3 Rewarded · 3 Duplicate/Known** — drawn from 37 Immunefi submissions across 20+ programs.

Each finding lives in [`findings/<severity>/<nn>-<slug>/`](findings/) with its full write-up
(`REPORT.md`), a short index (`README.md`), and the original submission text (`ISSUE-1.md`).

> Severity labels below are the program's **final** rating. Where a project downgraded an
> initially-higher submission (e.g. Zano High→Low), the final rating is used and the original
> is noted in the write-up.

---

## Rewarded

| # | Target | Finding | Final Severity | Reward | Folder |
|---|--------|---------|----------------|--------|--------|
| 04 | monero-oxide (`monero-oxide/wallet`) | Off-by-one in decoy selection excludes the real output from the first RPC batch → true-spend fingerprint | Medium | **$2,500 (XMR)** | [`04-monero-oxide-decoy-offbyone-true-spend-fingerprint`](findings/medium/04-monero-oxide-decoy-offbyone-true-spend-fingerprint/) |
| 05 | Zano (`core_default_rpc_proxy.cpp`) | Wallet↔daemon HTTPS connection skips TLS certificate validation → MITM over RPC | Low | **$1,000 (USDC)** | [`05-zano-daemon-rpc-missing-tls-validation-mitm`](findings/low/05-zano-daemon-rpc-missing-tls-validation-mitm/) |
| 06 | Zano (`wallet_rpc_server.cpp`) | JWT anti-replay salts held in-memory only → signed RPC commands replayable across restart | Low | **$1,000 (USDC)** | [`06-zano-jwt-salt-not-persisted-rpc-replay`](findings/low/06-zano-jwt-salt-not-persisted-rpc-replay/) |

## Duplicate / already-known (accepted as real, prior report claimed the reward)

| # | Target | Finding | Severity | Status | Folder |
|---|--------|---------|----------|--------|--------|
| 01 | Utix (`MintedTokenCappedCrowdsaleExtv1`, mainnet) | `extcodesize==0` withdrawal guard rejects the Gnosis-Safe multisig → 451 ETH permanently locked | Critical | Duplicate of #22566 (Immunefi-verified same root cause) | [`01-utix-eoa-only-withdrawal-guard-451eth-lock`](findings/critical/01-utix-eoa-only-withdrawal-guard-451eth-lock/) |
| 02 | Zano (`core_rpc_server.cpp`) | `reset_transaction_pool` admin RPC purges the mempool with no auth | Critical | Duplicate of #49357 | [`02-zano-unauth-admin-rpc-mempool-purge`](findings/critical/02-zano-unauth-admin-rpc-mempool-purge/) |
| 03 | Zano (`tx_pool.cpp`) | No early size/input/output/proof-complexity bound on accepted txs → resource-exhaustion DoS | High | Acknowledged known issue (roadmap: Dynamic fee) | [`03-zano-txpool-unbounded-tx-resource-exhaustion`](findings/high/03-zano-txpool-unbounded-tx-resource-exhaustion/) |

---

## What "outcome-verified" means here

Each finding cleared a bar before being included:

1. **Submitted to a live program** on Immunefi, with a full write-up and reproduction steps.
2. **Runnable PoC** — a test, script, or exact command sequence that demonstrates the issue,
   not a hypothetical.
3. **Terminal, favorable outcome** — the program either **paid a reward**, or **closed the
   report as a duplicate / already-known issue**. In both cases the vulnerability itself was
   real and accepted; the duplicate closures simply mean a prior researcher reported it first.

Reports that a program rejected **on the merits** (invalid, out-of-scope, working-as-intended,
or low-quality) are not included, even where I disagreed with the decision.

## Per-finding notes

- **#01 Utix** — Immunefi's own technical team confirmed this is the *same root cause* as the
  earlier Report #22566 before closing it; the 451 ETH lock is a genuine, still-relevant issue
  on a deployed mainnet contract.
- **#02 Zano** — closed as a duplicate of Report #49357; the unauthenticated admin-RPC purge
  requires the node to run with `--rpc-enable-admin-api` bound to a public interface.
- **#03 Zano** — the team acknowledged this is a known limitation already tracked under their
  "Dynamic fee implementation" roadmap milestone, which will price transactions by input count.
- **#04 monero-oxide** — rewarded $2,500 in XMR. The project noted the *created transaction*
  itself is not fingerprintable; the leak is in the **RPC candidate-query pattern** visible to a
  malicious/observing remote node — a real privacy issue they chose to reward on practical impact.
- **#05 / #06 Zano** — both rewarded. Zano downgraded each from its submitted severity
  (High→Low, Critical→Low) citing the local-network / local-malware precondition, then confirmed
  and paid.

## Deliberately excluded

Kept out so the portfolio contains only accepted findings:

- **XION #53298** (`deploy_fee_grant` access control) — Immunefi mediation reviewed it and ruled
  it should **remain closed on the merits** (the function's grant-config check does gate the
  grantee); notably mediation also found it was **not** a true duplicate of #22566. Real analysis,
  but rejected — excluded.
- **Zano #50243** (Zarcanum fee-field bypass), **#49637** (decoy modulo bias), **#49488**
  (`set_appconfig` path traversal), **#50069** (escrow multisig), **#50245**/**#50330** — closed
  as low-quality or out-of-scope on the merits.
- **USX #60179**, **Vechain/Stargate #59255**, **Jito-BAM #57690**, **monero-oxide #55515**,
  **Nodle #55400**, **XOXNO #55020/#55000/#54897**, **Enzyme #54305/#54302/#54275/#54242**,
  **Ondo #54057**, **ZKsync Lite #53519/#53456**, **Zano #53378**, **Balancer #53368**,
  **Sei #51787/#51687**, **Arbitrum #51136**, **Lido #51048**, **BiFi #50767**, **Orca #50673**,
  **Rocket Pool #50581**, **AAVE #50536/#50514**, **The Graph #37129**, **Immunefi #37142** —
  all rejected on the merits (invalid / intended-behavior / out-of-scope / self-griefing).

## Responsible disclosure

These findings were reported through Immunefi's official channels and have reached terminal
status. Each program's publication category governs what may be shared; where a project requires
a review window or approval before public disclosure, that is respected. PoCs here describe the
same steps submitted to the program.

---

*Whitehat: [@AnticsDecoded](https://bugs.immunefi.com/) on Immunefi · Intermediate · Leaderboard #1117*
