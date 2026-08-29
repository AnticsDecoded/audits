# Low: Wallet↔daemon HTTPS connection skips TLS certificate validation → MITM over RPC

**Target:** Zano (`hyle-team/zano/src/wallet/core_default_rpc_proxy.cpp`)
**Severity:** Low
**Slug:** `zano-daemon-rpc-missing-tls-validation-mitm`

## Impact

When the Zano wallet connects to a daemon over `https`, it enables SSL transport but performs
**no validation of the server's TLS certificate** — no CA/issuer check, no hostname match, no
expiry check. Any host presenting a self-signed certificate is accepted silently. An attacker
positioned on the network path (DNS spoofing, hostile LAN, rogue public node) can MITM the
wallet↔daemon channel and read or tamper with all RPC traffic: `/getinfo`,
`/sendrawtransaction`, `/getblocktemplate`, alias queries, and more.

## Root cause

```cpp
if (u.schema == "https") {
    m_http_client.set_is_ssl(true);   // enables SSL, but never verifies the peer certificate
}
```

`set_is_ssl(true)` turns on TLS but does not attach any peer-verification callback, so the
handshake succeeds against any certificate.

## Proof of Concept

Stand up a fake HTTPS "daemon" with a self-signed cert and point the wallet at it; the wallet
connects with no warning and sends its RPC traffic to the attacker-controlled endpoint. Full
steps in [`ISSUE-1.md`](./ISSUE-1.md).

## Files in this folder

- [`REPORT.md`](./REPORT.md) — full technical write-up
- [`ISSUE-1.md`](./ISSUE-1.md) — finding submission
- [`POC__fake_https_daemon.sh`](./POC__fake_https_daemon.sh) — reproduction script (self-signed HTTPS daemon)
