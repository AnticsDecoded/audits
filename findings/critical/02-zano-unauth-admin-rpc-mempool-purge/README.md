# Critical (Duplicate of #49357): `reset_transaction_pool` admin RPC purges the mempool with no authentication

**Target:** Zano (`hyle-team/zano/src/rpc/core_rpc_server.cpp`)
**Program:** [Zano on Immunefi](https://bugs.immunefi.com/) — Bug Bounty
**Submission:** #50228 · Submitted 2025-07-22
**Severity:** Critical · **Outcome:** Closed as **duplicate of Report #49357**
**Slug:** `zano-unauth-admin-rpc-mempool-purge`

## Impact

`zanod` exposes the admin RPC method `reset_transaction_pool`, which calls
`purge_transactions()` directly with no token, header, or authentication check. When the daemon
runs with `--rpc-enable-admin-api` and binds a public interface (`--rpc-bind-ip 0.0.0.0`), any
remote party can clear the entire mempool with a single unauthenticated HTTP POST — repeatedly —
disrupting transaction propagation and stalling confirmations for clients that depend on the node.

## Root cause

```cpp
bool core_rpc_server::on_reset_transaction_pool(
    const COMMAND_RPC_RESET_TX_POOL::request& req,
    COMMAND_RPC_RESET_TX_POOL::response& res,
    connection_context& cntx)
{
    m_core.get_tx_pool().purge_transactions();   // no auth / access-control / caller check
    res.status = API_RETURN_CODE_OK;
    return true;
}
```

The handler is reachable whenever `--rpc-enable-admin-api` is set; it performs no validation of
the requestor before purging the pool.

## Proof of Concept

Start a node with `--rpc-enable-admin-api --rpc-bind-ip 0.0.0.0`, then an unauthenticated
`curl` POST of `{"method":"reset_transaction_pool"}` returns `{"status":"OK"}` and empties the
pool. Full steps in [`ISSUE-1.md`](./ISSUE-1.md).

## Outcome / notes

Closed by Zano as a duplicate of Report #49357 — the underlying issue is accepted; a prior
researcher reported it first. The impact is conditional on the node being run with the admin API
enabled and publicly bound.

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — original Immunefi submission (#50228)
- [`POC__reset_tx_pool.sh`](./POC__reset_tx_pool.sh) — reproduction script
