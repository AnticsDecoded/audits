# Zano — `reset_transaction_pool` admin RPC purges the mempool with no authentication

| | |
|---|---|
| **Program** | Zano (Immunefi Bug Bounty) |
| **Submission** | #50228 |
| **Target** | `hyle-team/zano/src/rpc/core_rpc_server.cpp` @ `master` |
| **Class** | Missing authentication / remote DoS (mempool manipulation) |
| **Severity** | Critical |
| **Outcome** | Closed — **duplicate of Report #49357** |

## 1. Summary

The `zanod` daemon exposes the admin RPC method `reset_transaction_pool`. Its handler calls
`purge_transactions()` immediately, with no authentication, token check, IP allowlist, or caller
validation. Any node started with `--rpc-enable-admin-api` and bound to a reachable interface
(e.g. `--rpc-bind-ip 0.0.0.0`) will honour a single unauthenticated HTTP POST that empties its
entire mempool — and will do so on every repeat.

## 2. Affected code

```cpp
bool core_rpc_server::on_reset_transaction_pool(
    const COMMAND_RPC_RESET_TX_POOL::request& req,
    COMMAND_RPC_RESET_TX_POOL::response& res,
    connection_context& cntx)
{
    m_core.get_tx_pool().purge_transactions();
    res.status = API_RETURN_CODE_OK;
    return true;
}
```

The only gate is the process-wide `--rpc-enable-admin-api` flag; there is no per-request
authorization on this destructive admin operation.

## 3. Impact

Against a node running with the admin API enabled on a public bind, a remote unauthenticated
attacker can:

- Purge all pending transactions from the node's mempool.
- Repeat continuously to suppress user transactions and keep the pool empty/unstable.
- Degrade transaction propagation and stall confirmations for light-wallet clients that rely on
  the node.
- Target public nodes, API endpoints, and infrastructure providers specifically.

## 4. Proof of Concept

[`POC__reset_tx_pool.sh`](./POC__reset_tx_pool.sh):

1. Run a testnet node: `zanod --rpc-enable-admin-api --rpc-bind-ip 0.0.0.0 --rpc-bind-port 8071 --testnet`.
2. Issue an unauthenticated POST of `{"method":"reset_transaction_pool","params":{}}`.
3. Response: `{"result":{"status":"OK"}}` — the pool is cleared with no credential supplied.

## 5. Remediation

- Require authentication/authorization for all admin-API methods (the same access-token layer the
  wallet RPC uses), not merely the presence of `--rpc-enable-admin-api`.
- Default admin methods to loopback-only and warn (or refuse) when the admin API is bound to a
  non-local interface.
- Treat state-mutating admin operations (`reset_transaction_pool`, etc.) as privileged and gate
  them behind an explicit token/allowlist.

## 6. Disclosure outcome

Zano closed this as a duplicate of Report #49357. The vulnerability is accepted as real; a prior
report claimed it first, so no reward issued. Impact is conditional on the operational choice to
enable the admin API on a public bind.
