# Medium: Off-by-one in decoy selection excludes the real output from the first RPC batch → true-spend fingerprint

**Target:** monero-oxide (`monero-oxide/monero-oxide/wallet/src/decoys.rs`)
**Severity:** Medium
**Slug:** `monero-oxide-decoy-offbyone-true-spend-fingerprint`

## Impact

The decoy-selection routine is *intended* to include the real output in the first RPC batch
sent to `DecoyRpc::get_unlocked_outputs`, so a node cannot later correlate "all decoys + one
extra" to find the true spend. A loop-counter off-by-one makes the "first iteration" guard
**never true**, so the real output is never added to that first batch. A malicious or on-path
node logs the first candidate set, waits for the ring to appear on-chain, and takes the
set-difference: the one ring member it was never asked about is the true spend. This
collapses the effective anonymity set to **1** for affected inputs — passive, no credentials,
no wallet compromise, no user interaction.

## Root cause

```rust
let mut iters = 0;
while res.len() != decoy_count {
    iters += 1;                 // incremented BEFORE the check
    // ...
    let real_index = if iters == 0 {   // can never be true — first pass sees iters == 1
        candidates.push(real_output);
        candidates.sort();
        Some(candidates.binary_search(&real_output).expect("…"))
    } else {
        None
    };
    // ...
}
```

`iters` starts at `0` and is incremented at the top of the loop, so the first pass sees
`iters == 1`. The real output is therefore never mixed into the first `get_unlocked_outputs`
query.

## Proof of Concept

A self-contained `#[tokio::test]` with a mock `DecoyRpc`
(`poc_deanonymize_via_first_candidates_set_difference`) records the first candidate list passed
to `get_unlocked_outputs`, runs the real `select_n`, then asserts that
`ring_indices \ first_candidates == [real_output]` — i.e. the real output is uniquely isolated by
set-difference. See [`ISSUE-1.md`](./ISSUE-1.md) for the full report and [`REPORT.md`](./REPORT.md)
for the write-up.

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — finding submission
- [`POC__decoys_first_candidates_setdiff.rs`](./POC__decoys_first_candidates_setdiff.rs) — mock-RPC unit-test PoC
