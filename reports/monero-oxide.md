## monero-oxide
[Program on Immunefi](https://bugs.immunefi.com/) · Target: [monero-oxide/monero-oxide](https://github.com/monero-oxide/monero-oxide)

`monero-oxide` is a Rust implementation of Monero primitives, including wallet-side ring
construction. The finding below concerns the decoy-selection routine that assembles the ring a
transaction spends against.

---

### [Medium-01] Off-by-one in decoy selection excludes the real output from the first RPC batch

**Target:** `monero-oxide/wallet/src/decoys.rs`

**Finding description and impact**

Monero-style ring signatures hide which output in a ring is actually being spent. The wallet builds
the ring by asking a daemon (`DecoyRpc`) about candidate outputs, and the code is *designed* to
include the real output in the very first RPC batch so a node observing the queries cannot later
distinguish the real spend from the decoys.

An off-by-one defeats this. The "first iteration" guard is keyed on `iters == 0`, but `iters` is
incremented to `1` before the check, so the branch is unreachable:

```rust
let mut iters = 0;
while res.len() != decoy_count {
    iters += 1;                        // (1) incremented at the top of the loop

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
    // candidates (WITHOUT real_output) are sent to get_unlocked_outputs(...)
}
```

Consequently the real output is never mixed into the first `get_unlocked_outputs` query. A
malicious or on-path node logs that first candidate set, waits for the transaction's ring to land
on-chain, and computes `ring \ first_candidates` — the single ring member it was never asked about
is the true spend. The leak is passive and unprivileged, independent of ring size or the gamma
distribution (it is *which* outputs were queried first, not how they were sampled), works for
single-sig and multisig, and is stealthy (RPC traffic looks normal). Effective anonymity set for an
affected input collapses from the ring size to **1**. Note the on-chain transaction itself is not
distinguishable — the exploitable signal lives in the RPC query pattern seen by a remote node.

**Proof of Concept**

A self-contained `#[tokio::test]` with a mock `DecoyRpc` records the first candidate list passed to
`get_unlocked_outputs`, runs the real `select_n`, and asserts the real output is uniquely isolated
by set-difference:

```rust
let diff: Vec<u64> = ring_indices.iter().copied()
    .filter(|i| !first_candidates.contains(i))
    .collect();
assert_eq!(diff, vec![real_output]);   // real output uniquely recoverable
```

Full test: [`poc/monero-oxide-decoys-setdiff-test.rs`](./poc/monero-oxide-decoys-setdiff-test.rs)

**Recommended mitigation steps**

Bind the "include the real output" step to the actual first iteration — either initialise the
counter to match the pre-increment or use a boolean set on the first pass:

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
