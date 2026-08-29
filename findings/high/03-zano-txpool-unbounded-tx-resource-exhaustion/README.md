# High (Acknowledged known issue): No early size/input/output/proof-complexity bound on accepted txs → resource-exhaustion DoS

**Target:** Zano (`hyle-team/zano/src/currency_core/tx_pool.cpp`)
**Program:** [Zano on Immunefi](https://bugs.immunefi.com/) — Bug Bounty
**Submission:** #50239 · Submitted 2025-07-22
**Severity:** High · **Outcome:** Closed — **acknowledged known issue** (roadmap: "Dynamic fee implementation")
**Slug:** `zano-txpool-unbounded-tx-resource-exhaustion`

## Impact

`tx_pool.cpp` does not enforce strict early limits on transaction size, input/output count, or
Zarcanum proof complexity before admitting a transaction into the mempool. An attacker can craft
oversized transactions (hundreds of inputs/outputs, heavy Zarcanum range proofs) whose validation
and propagation consume disproportionate CPU and memory — spiking node resource usage (>30% in
testing), delaying legitimate transaction processing, and risking mempool overflow on lower-spec
nodes.

## Root cause

```cpp
bool tx_memory_pool::add_tx(const transaction &tx, ...)
```

`add_tx` processes the raw tx blob but has no early upper-bound rejection on:

- total transaction size,
- number of inputs,
- number of outputs,
- Zarcanum proof complexity (Pedersen commitments / surjection & range proofs).

Oversized transactions are accepted and then bottleneck mempool verification.

## Proof of Concept

Build a testnet node, construct a Zarcanum transaction with 200+ inputs and 200+ outputs, submit
via `send_raw_tx`, and observe the node's CPU spike and reduced responsiveness to normal
transactions. Steps in [`ISSUE-1.md`](./ISSUE-1.md).

## Outcome / notes

Zano acknowledged the issue is already known and planned for their **"Dynamic fee
implementation"** roadmap milestone, which will use the transaction input count to justify fees
(pricing the abuse vector). Because a prior report/roadmap item already covers it, no reward was
issued — but the underlying weakness is accepted as valid.

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — original Immunefi submission (#50239)
- [`POC__oversized_tx.md`](./POC__oversized_tx.md) — reproduction notes
