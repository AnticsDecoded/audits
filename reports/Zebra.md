## Zebra (Zcash Foundation)
Coordinated disclosure · Target: [ZcashFoundation/zebra](https://github.com/ZcashFoundation/zebra)

Zebra is the Zcash Foundation's Rust implementation of a Zcash full node (`zebrad`). The finding
below is in the mempool transaction-download pipeline.

- **Advisory:** [GHSA-65jj-fmw8-468q](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-65jj-fmw8-468q)
- **CVE:** CVE-2026-52734
- **Affected:** `zebrad` ≤ 4.4.1 · **Patched:** 4.5.0
- **Weakness:** CWE-401 / CWE-772 (missing release of memory after effective lifetime)

---

### [Medium-01] Unbounded memory leak in the mempool download pipeline via the timeout path

**Target:** `zebrad/src/components/mempool/downloads.rs` (`Downloads::poll_next()`, lines ~215–228)

**Finding description and impact**

The mempool download pipeline tracks in-flight transaction verifications in a `cancel_handles`
map, keyed by `UnminedTxId`, where each entry holds the full deserialized transaction (up to
~2 MB). `Downloads::poll_next()` removes an entry on both success and verification error by
calling `cancel_handles.remove()` — but the **timeout** arm returns without cleanup.

Verification is bounded by a 73-second rate-limit timeout. When that fires, the task resolves to
`Err(tokio::time::error::Elapsed)`. Because `Elapsed` carries **no payload**, the associated
`UnminedTxId` is unrecoverable at that point, so the timeout arm cannot look up and remove the
`cancel_handles` entry:

```rust
// Downloads::poll_next() — shape of the defect
match ready!(self.pending.poll_next_unpin(cx)) {
    Some(Ok((tx, tx_id)))  => { self.cancel_handles.remove(&tx_id); /* ... */ }
    Some(Err((tx_id, e)))  => { self.cancel_handles.remove(&tx_id); /* verification error */ }
    Some(Err(elapsed))     => { /* tokio Elapsed: no tx_id -> entry is never removed */ }
    // ...
}
```

The consumer at `zebrad/src/components/mempool.rs:663–672` acknowledges the gap with a `TODO`.

As a result, every timed-out download leaks its `cancel_handles` entry permanently. Entries
accumulate monotonically with no garbage collection and no upper bound. The trigger is ordinary
**unauthenticated P2P traffic** from remote peers, so a remote attacker (or simply adverse network
conditions at scale) can drive the leak at roughly **685 KB/s per connection** in the worst case,
eventually exhausting memory and causing the node to be OOM-killed or to degrade under swap
pressure. Consensus, funds, and on-disk data integrity are unaffected — the impact is availability.

**Conditions for exploitation**

- Running `zebrad` v4.4.1 or earlier,
- with inbound P2P connections enabled (default), and
- an active mempool (synced near the chain tip).

**Proof of Concept**

No configuration-level workaround exists; a node restart clears the accumulated entries. The leak
is observable by driving mempool downloads that hit the 73-second rate-limit timeout and watching
`zebrad` resident memory grow without bound while the `cancel_handles` map never shrinks. See
[`poc/zebra-mempool-leak.md`](./poc/zebra-mempool-leak.md) for reproduction/observation notes.

**Recommended mitigation steps**

Preserve the `UnminedTxId` through the timeout error path so the entry can be cleaned up. Wrap the
timeout future so the spawned task's outer error carries the transaction ID (e.g.
`Err((txid, elapsed))`), and in the timeout arm of `Downloads::poll_next()` call
`self.cancel_handles.remove(&txid)`:

```rust
Some(Err((tx_id, _elapsed))) => {
    self.cancel_handles.remove(&tx_id);   // timeout path now releases the entry
    // ... surface the timeout to the consumer as before
}
```

Fixed in `zebrad` 4.5.0.
