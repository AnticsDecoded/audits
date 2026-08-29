# monero-oxide — Decoy-selection off-by-one leaks the true spend to a remote node

| | |
|---|---|
| **Program** | monero-oxide (Immunefi Bug Bounty) |
| **Submission** | #54470 |
| **Target** | `monero-oxide/monero-oxide/wallet/src/decoys.rs` @ `main` |
| **Class** | Privacy / deanonymization (ring-signature anonymity-set collapse) |
| **Submitted severity** | Medium |
| **Final outcome** | **Rewarded — 9.434 XMR (~$2,500 USD)** |

## 1. Summary

Monero-style ring signatures hide which output in a ring is actually being spent. `monero-oxide`'s
wallet builds the ring by asking a daemon (`DecoyRpc`) about candidate outputs. To avoid an
obvious correlation attack, the code is designed to **include the real output in the very first
RPC batch** of candidates, so that a node observing the queries cannot later distinguish the
real spend from the decoys.

An off-by-one in the loop counter defeats this: the guard that should fire on the first
iteration (`iters == 0`) can never be true, because `iters` is incremented to `1` before the
check. The real output is consequently **omitted from the first `get_unlocked_outputs` query**.
A malicious or on-path node logs that first candidate set, waits for the transaction's ring to
land on-chain, and computes the set difference — the single ring member it was never asked about
is the true spend.

## 2. Affected code

`monero-oxide/wallet/src/decoys.rs`, inside the decoy-selection loop:

```rust
let mut iters = 0;
while res.len() != decoy_count {
    iters += 1;                        // (1) incremented at the top of the loop

    // ...

    let real_index = if iters == 0 {   // (2) intended "first iteration" guard — dead code
        candidates.push(real_output);
        candidates.sort();
        Some(
            candidates
                .binary_search(&real_output)
                .expect("selected a ring which didn't include the real spend"),
        )
    } else {
        None
    };

    // candidates (without real_output) are sent to get_unlocked_outputs(...)
}
```

Because of `(1)`, the first pass through the loop already has `iters == 1`, so the branch at
`(2)` is unreachable. The real output is never mixed into the first candidate set.

## 3. Why it matters

The intended design mixes the real output into the first query precisely so the "first batch"
is indistinguishable from every later batch. With the guard dead:

- **First batch = decoys only.** The node observes a candidate set that provably excludes the
  spend.
- **On-chain ring = decoys + real.** Once broadcast, the ring is public.
- **Set difference = the spend.** `ring \ first_candidates` yields exactly one element: the real
  output.

Properties of the leak:

- **Passive & unprivileged.** Any node the wallet talks to — or any on-path observer of
  unencrypted/only-server-authenticated RPC — can do this. No wallet compromise, no user action.
- **Ring-size / distribution independent.** The leak is *which outputs were queried first*, not
  how decoys were sampled, so gamma-distribution correctness doesn't help.
- **Works for single-sig and multisig.**
- **Stealthy & persistent.** RPC traffic looks normal; there is no on-chain or UI signal.

Effective anonymity set for an affected input collapses from the ring size to **1**.

## 4. Proof of Concept

[`POC__decoys_first_candidates_setdiff.rs`](./POC__decoys_first_candidates_setdiff.rs) is a
self-contained `#[tokio::test]` that:

1. Implements a mock `DecoyRpc` recording the **first** `candidates` slice it receives.
2. Runs the real `select_n(...)` against it.
3. Reconstructs `ring_indices = decoys ∪ {real_output}`.
4. Asserts `ring_indices \ first_candidates == [real_output]`.

The assertion passes, demonstrating that the real output is uniquely recoverable by
set-difference from data a node legitimately sees.

```
first_candidates.len() = <ring_len-1 worth of decoys>
ring_indices.len()     = <ring_len>
real_output            = 123456
difference             = [123456]
```

## 5. Remediation

Bind the "include the real output" step to the actual first iteration. Either initialise the
counter to reflect the pre-increment (`iters == 1` in the current structure), or restructure so
the guard uses a boolean set on the first pass:

```rust
let mut first = true;
while res.len() != decoy_count {
    let real_index = if first {
        first = false;
        candidates.push(real_output);
        candidates.sort();
        Some(candidates.binary_search(&real_output).expect("…"))
    } else {
        None
    };
    // ...
}
```

This restores the intended property that the real output is present in the first
`get_unlocked_outputs` query, so no batch is distinguishable by inclusion/exclusion of the spend.

## 6. Disclosure outcome

The maintainers agreed the behaviour is real but classed the *submitted* impact wording
(fingerprint in the created transaction) as out-of-scope, since the on-chain transaction is not
itself distinguishable — the exploitable signal is in the RPC query pattern seen by a malicious
remote node. On practical impact they awarded **$2,500 in XMR**
(tx `d67682ba2f324ff247a0cdaf66f705d70c964f323bfc8604a00e4fff4b272a27`).
