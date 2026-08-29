# Reproduction / observation notes — Zebra mempool `cancel_handles` leak (CVE-2026-52734)

Advisory: https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-65jj-fmw8-468q
Affected: `zebrad` ≤ 4.4.1 · Fixed: 4.5.0

## What is leaking

`Downloads` (in `zebrad/src/components/mempool/downloads.rs`) keeps a `cancel_handles: HashMap<UnminedTxId, _>`
where each in-flight entry retains the full deserialized transaction (up to ~2 MB). Entries are
removed on success and on verification error, but **not** when the per-download 73-second
rate-limit timeout fires — because `tokio::time::error::Elapsed` carries no transaction id, the
timeout arm of `poll_next()` cannot identify which entry to remove. Timed-out downloads therefore
leak their entry permanently; the map grows monotonically with no bound.

## Observing the leak

1. Build and run an affected node (`zebrad` ≤ 4.4.1) with default config (inbound P2P enabled),
   synced near the chain tip so the mempool is active.
2. Record baseline resident memory:
   ```bash
   pid=$(pgrep zebrad)
   while true; do ps -o rss= -p "$pid" | awk '{printf "%.1f MB\n", $1/1024}'; sleep 5; done
   ```
3. Drive mempool downloads that hit the 73-second rate-limit timeout (a stream of advertised
   transactions over P2P such that verification does not complete within the rate-limit window).
   Each timed-out download adds a `cancel_handles` entry that is never released.
4. Observe RSS climbing without bound over time (~685 KB/s per connection worst case), with no
   plateau, until the OS OOM killer terminates `zebrad` or it degrades under swap pressure.
5. Restart clears the accumulated entries (the only mitigation prior to 4.5.0); there is no
   configuration-level workaround.

## Confirming the root cause

Instrument or log `cancel_handles.len()` in `Downloads::poll_next()`: under the load above it
increases monotonically and never decreases on the timeout path, while success/error paths do
decrement it. On 4.5.0 the count returns to baseline because the timeout arm now removes the entry
via the transaction id threaded through `Err((txid, elapsed))`.
