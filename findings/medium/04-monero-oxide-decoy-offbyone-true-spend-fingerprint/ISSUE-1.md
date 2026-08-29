# Off-by-one in decoy selection lets the RPC node identify the true spend

**Target:** https://github.com/monero-oxide/monero-oxide/tree/main — Blockchain/DLT

## Brief / Intro

I found an off-by-one bug in the decoy selection routine that causes the real output to never
be included in the first RPC query for candidate outputs. A connected or intercepted node can
record all outputs it's asked about, and when the final ring is later broadcast on-chain,
trivially spot the one output it was never asked about as the true spend — an undocumented
fingerprint that degrades sender privacy and enables reliable deanonymization of spends.

## Vulnerability Details

The implementation intends to include the real output in the first batch sent to
`DecoyRpc::get_unlocked_outputs` so the node cannot later correlate "all decoys + one extra"
to find the true spend.

However, the loop counter is incremented before the "first iteration" check, so the condition
to add the real output can never be true:

```rust
let mut iters = 0;
while res.len() != decoy_count {
    iters += 1;  // <-- incremented here

    // ...

    // Intended: include the real output in the first batch
    let real_index = if iters == 0 {  // <-- this is never true
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

    // ...
}
```

Because `iters` starts at 0 and is incremented at the top of the loop, the first pass sees
`iters == 1`, not `0`.

As a result:

- The real output is never added to the initial `candidates` list.
- The first call to `get_unlocked_outputs(&candidates, ...)` therefore touches only decoys.
- When the transaction is eventually constructed and the ring appears on-chain, the node
  compares: "decoy candidates I was asked about" vs. "members of the final ring".
- The one ring member that was never requested must be the true spend.

## Impact Details

This vulnerability allows an attacker to:

- Identify the true spend in each Monero ring by passively logging the wallet's first
  decoy-candidate RPC and later taking the set difference with the on-chain ring.
- Deanonymize users at scale as a node operator or on-path observer with no credentials, no
  wallet compromise, no user interaction required.
- Track both single-sig and multisig transactions, regardless of ring size or gamma
  distribution, because the leak is *which outputs were queried first*, not how they were sampled.
- Persist the attack across restarts and remain stealthy. RPC traffic looks normal; there's no
  UI or on-chain signal to the victim.
- Cluster wallets and map payment flows over time, enabling user profiling, counterpart
  identification, and relationship inference.
- Bypass Monero's intended anonymity set, effectively collapsing it to 1 for affected inputs.

## References

- Vulnerable code: https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/wallet/src/decoys.rs

## Proof of Concept

I showed that during decoy selection the real output is not included in the first RPC request
when it should be, which lets a node later identify the true spend by simple set-difference.

I added a tiny unit test and a mock RPC to `decoys.rs` so it runs in place. The test records
the first candidates passed to `get_unlocked_outputs(...)` and asserts the real output wasn't
in that list. See [`POC__decoys_first_candidates_setdiff.rs`](./POC__decoys_first_candidates_setdiff.rs).
