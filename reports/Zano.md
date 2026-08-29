## Zano
[Program on Immunefi](https://bugs.immunefi.com/) · Target: [hyle-team/zano](https://github.com/hyle-team/zano)

Zano is a privacy-focused Layer 1 (CryptoNote / Zarcanum lineage) with a C++ daemon (`zanod`)
and wallet. The findings below span the daemon's admin RPC surface, the mempool acceptance path,
the wallet↔daemon transport, and the wallet RPC authentication layer.

---

### [Critical-01] Unauthenticated `reset_transaction_pool` admin RPC purges the mempool

**Target:** `src/rpc/core_rpc_server.cpp`

**Finding description and impact**

`zanod` exposes the admin RPC method `reset_transaction_pool`, whose handler calls
`purge_transactions()` directly with no token, header, or caller check. When the daemon runs with
`--rpc-enable-admin-api` and binds a reachable interface (`--rpc-bind-ip 0.0.0.0`), any remote
party can clear the node's entire mempool with a single unauthenticated HTTP POST — and repeat it
indefinitely.

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

The only gate is the process-wide `--rpc-enable-admin-api` flag; there is no per-request
authorization on this destructive operation. Against an exposed node an attacker can delete all
pending transactions, suppress user transactions by repeated resets, stall confirmations for
light-wallet clients that depend on the node, and specifically target public nodes and
infrastructure providers.

**Proof of Concept**

Run a testnet node with the admin API enabled and publicly bound, then issue an unauthenticated
request:

```bash
zanod --rpc-enable-admin-api --rpc-bind-ip 0.0.0.0 --rpc-bind-port 8071 --testnet

curl -X POST http://127.0.0.1:8071/json_rpc \
  -H "Content-Type: application/json" \
  -d '{ "jsonrpc": "2.0", "id": "0", "method": "reset_transaction_pool", "params": {} }'
# -> { "id": "0", "jsonrpc": "2.0", "result": { "status": "OK" } }  (mempool cleared, no credential)
```

Script: [`poc/zano-reset-tx-pool.sh`](./poc/zano-reset-tx-pool.sh)

**Recommended mitigation steps**

Require the same access-token authorization the wallet RPC uses for all admin-API methods rather
than merely the presence of `--rpc-enable-admin-api`; default admin methods to loopback-only and
refuse (or loudly warn) when the admin API is bound to a non-local interface; treat every
state-mutating admin operation as privileged behind an explicit token/allowlist.

---

### [High-02] Unbounded transaction acceptance in `tx_pool` enables resource-exhaustion DoS

**Target:** `src/currency_core/tx_pool.cpp`

**Finding description and impact**

`tx_memory_pool::add_tx` admits incoming transactions into the mempool without any early
upper-bound check on transaction size, input count, output count, or Zarcanum proof complexity.
An attacker can craft a single very large Zarcanum transaction — hundreds of inputs and outputs
with heavy range/surjection proofs — that is accepted first and only then made to undergo
expensive cryptographic verification, disproportionately consuming node CPU and memory and
delaying legitimate traffic. Repeated submissions amplify the effect and risk mempool overflow on
lower-spec nodes.

```cpp
bool tx_memory_pool::add_tx(const transaction &tx, ...)
// no early rejection on: total tx size, #inputs, #outputs, Zarcanum proof element count
```

In testing this spiked node CPU by more than 30% over baseline while verifying the oversized
proofs, degraded RPC responsiveness for wallet and miner nodes, and needed no brute force — one
crafted transaction, repeated, is enough.

**Proof of Concept**

On a testnet node, build a Zarcanum transaction with 200+ inputs and 200+ outputs, submit it via
`send_raw_tx`, and sample CPU/responsiveness before vs. during:

```bash
curl -X POST http://127.0.0.1:<rpc-port>/json_rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "send_raw_tx", "params": {"tx_as_hex": "<oversized_tx_hex>"}}'
```

Full notes: [`poc/zano-oversized-tx.md`](./poc/zano-oversized-tx.md)

**Recommended mitigation steps**

Add cheap, early bounds in `add_tx` (and its relay/validation callers) that reject transactions
exceeding sane maxima for size, input count, output count, and proof-element count **before**
running expensive verification, and price fees by input count so the economic cost of large
transactions tracks their verification cost.

---

### [Low-03] Wallet↔daemon HTTPS connection performs no TLS certificate validation

**Target:** `src/wallet/core_default_rpc_proxy.cpp`

**Finding description and impact**

When the wallet connects to a daemon over `https`, it enables SSL transport but installs no
certificate verification — no CA/issuer check, no hostname match, no expiry check. The TLS
handshake therefore succeeds against any certificate, including self-signed ones.

```cpp
if (u.schema == "https") {
    m_http_client.set_is_ssl(true);   // enables SSL, but never verifies the peer certificate
}
```

An attacker on the network path (DNS spoofing, hostile LAN, a rogue public node) can transparently
MITM the wallet↔daemon channel and read or tamper with all RPC traffic — `/getinfo`,
`/sendrawtransaction`, `/getblocktemplate`, alias queries — serving fake sync state or block
templates, poisoning alias resolutions, or dropping transaction broadcasts. The practical
precondition is a hostile-network position.

**Proof of Concept**

Stand up a self-signed HTTPS "daemon" and point the wallet at it; the wallet connects with no TLS
warning and sends its RPC traffic to the attacker-controlled endpoint:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=fake.zano-daemon.com"
python3 -m http.server 8081 --directory ./fake_daemon --bind 127.0.0.1 \
  --certfile cert.pem --keyfile key.pem
# wallet daemon_address = https://127.0.0.1:8081  -> connects, cert silently accepted
```

Script: [`poc/zano-tls-fake-daemon.sh`](./poc/zano-tls-fake-daemon.sh)

**Recommended mitigation steps**

Enable real peer verification on the HTTPS path (`SSL_VERIFY_PEER` against a trusted CA store),
enforce hostname matching against the configured daemon address, reject expired/not-yet-valid
certificates, and for self-hosted daemons support explicit certificate or public-key pinning
configured out-of-band rather than accepting any certificate by default.

---

### [Low-04] JWT anti-replay salts are not persisted, enabling RPC command replay across restart

**Target:** `src/wallet/wallet_rpc_server.cpp`

**Finding description and impact**

The wallet RPC server authenticates each request with a JWT carrying a per-request `salt`,
intended to make each token single-use. The set of consumed salts (`m_jwt_used_salts`) lives only
in process memory:

```cpp
if (m_jwt_used_salts.get_set().find(salt) != m_jwt_used_salts.get_set().end()) {
    throw std::runtime_error("Salt reused");
}
// ...
m_jwt_used_salts.add(salt, ticks_now + JWT_TOKEN_EXPIRATION_MAXIMUM);
```

On restart the salt history is empty again, so a previously-seen, still-unexpired JWT (valid up to
~1 hour) — together with the exact request body it authorises via `body_hash` — can be replayed
verbatim, re-executing sensitive authenticated methods (`transfer`, `sweep_below`,
`contracts_release`) without fresh authentication. The JWT layer is used for localhost traffic
between the browser extension and the desktop wallet, so the practical precondition is an attacker
able to observe that local traffic.

**Proof of Concept**

Sign one `transfer` JWT (with `body_hash` over the request), submit it, restart the wallet RPC
with the same secret, and replay the identical token + body — it is accepted a second time:

```bash
# 1) send original request with Zano-Access-Token: <jwt>  --data @transfer.json
# 2) pkill simplewallet; relaunch with the SAME --jwt-secret
# 3) replay identical token + body  -> accepted again (transfer re-executes)
```

Script: [`poc/zano-jwt-replay.sh`](./poc/zano-jwt-replay.sh)

**Recommended mitigation steps**

Persist consumed salts (or a monotonic per-client nonce high-water mark) to durable storage scoped
by the token validity window so the replay guard survives restarts; bound the maximum allowed
`exp` claim to shrink the replay window; optionally bind tokens to a server-side session/epoch
value that rotates on restart so pre-restart tokens are rejected regardless of salt state.
