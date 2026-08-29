# Zano — `tx_pool` admits unbounded transactions, enabling resource-exhaustion DoS

| | |
|---|---|
| **Program** | Zano (Immunefi Bug Bounty) |
| **Submission** | #50239 |
| **Target** | `hyle-team/zano/src/currency_core/tx_pool.cpp` @ `master` |
| **Class** | Denial of service (missing input-validation bounds) |
| **Severity** | High |
| **Outcome** | Closed — **acknowledged known issue** (roadmap: Dynamic fee implementation) |

## 1. Summary

`tx_memory_pool::add_tx` accepts incoming transactions into the mempool without an early
upper-bound check on transaction size, input count, output count, or Zarcanum proof complexity.
An attacker can craft a single very large Zarcanum transaction — hundreds of inputs and outputs
with heavy range/surjection proofs — that is admitted first and only then made to undergo
expensive cryptographic verification, disproportionately consuming node CPU/memory and delaying
legitimate traffic. Repeated submissions amplify the effect and risk mempool overflow on
lower-spec nodes.

## 2. Affected code

```cpp
bool tx_memory_pool::add_tx(const transaction &tx, ...)
```

The path processes the raw tx blob but does not reject early on:

- **total tx size**,
- **number of inputs**,
- **number of outputs**,
- **Zarcanum proof complexity** (Pedersen commitments, surjection & range proofs).

Because rejection (if any) happens late, the costly verification work is performed on
attacker-sized inputs before the transaction can be discarded.

## 3. Impact

- CPU spikes measurably (>30% over baseline in testing) while verifying oversized proofs — meeting
  the program's "increasing node resource consumption by ≥30%" impact category.
- Mempool load rises, delaying legitimate transaction processing.
- RPC latency increases for wallet and miner nodes.
- Lower-spec nodes risk mempool overflow.

The vector needs no brute force — one crafted transaction (repeated) is enough.

## 4. Proof of Concept

[`POC__oversized_tx.md`](./POC__oversized_tx.md): run a testnet node, build a Zarcanum
transaction with 200+ inputs and 200+ outputs, submit via `send_raw_tx`, and measure the CPU
spike and reduced responsiveness. Baseline vs. attack-window CPU sampling substantiates the ≥30%
resource-increase category.

## 5. Remediation

Add cheap, early bounds in `add_tx` (and its relay/validation callers) that reject transactions
exceeding sane maxima for size, input count, output count, and proof-element count **before**
running expensive verification. Pair this with fee pricing that scales with input count so the
economic cost of large transactions tracks their verification cost.

## 6. Disclosure outcome

Zano acknowledged the issue is already known and tracked under their **"Dynamic fee
implementation"** roadmap milestone (fees justified by input count). As an already-covered item
it received no reward, but the weakness itself is accepted as valid — hence its inclusion here as
a known/acknowledged finding.
