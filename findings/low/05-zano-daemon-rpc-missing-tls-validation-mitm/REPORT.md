# Zano — Wallet daemon RPC connection performs no TLS certificate validation

| | |
|---|---|
| **Program** | Zano (Immunefi Bug Bounty) |
| **Submission** | #49512 |
| **Target** | `hyle-team/zano/src/wallet/core_default_rpc_proxy.cpp` @ `master` |
| **Class** | Transport security / MITM (missing certificate verification) |
| **Submitted severity** | High |
| **Final severity** | Low (project downgrade) |
| **Outcome** | **Confirmed & Rewarded — 1000 USDC** |

## 1. Summary

The Zano wallet talks to its daemon over HTTP or HTTPS via `core_default_rpc_proxy.cpp`. On the
`https` path it flips the client into SSL mode but never installs any certificate-verification
step. The TLS handshake therefore completes against **any** certificate — self-signed, wrong
hostname, expired, or attacker-issued. An adversary who can place themselves on the network path
between wallet and daemon can transparently intercept and modify all RPC traffic.

## 2. Affected code

```cpp
if (u.schema == "https") {
    m_http_client.set_is_ssl(true);
}
```

`set_is_ssl(true)` enables the TLS transport but attaches no peer-verification callback and sets
no verify mode. There is no check of:

- certificate authenticity / chain to a trusted CA,
- issuer,
- hostname (CN/SAN) vs. the daemon address,
- validity period (expiry / not-before).

## 3. Attack scenario

1. The victim's wallet is configured (or tricked via DNS spoofing / hostile LAN / a rogue public
   node advertisement) to reach `https://<attacker>`.
2. The attacker terminates TLS with a self-signed certificate.
3. The wallet accepts it silently and proceeds to issue RPC calls.
4. The attacker now controls the channel and can:
   - **Read** `/getinfo`, `/getblocktemplate`, `/sendrawtransaction`, `/getaliases`, transaction
     metadata and broadcast attempts;
   - **Tamper**: serve fake sync height/block templates, inject poisoned alias resolutions, or
     drop/modify transaction broadcasts.

## 4. Proof of Concept

[`POC__fake_https_daemon.sh`](./POC__fake_https_daemon.sh) generates a self-signed cert, serves a
minimal fake daemon over HTTPS on `127.0.0.1:8081`, and instructs the operator to point the
wallet at it. The wallet connects with **no TLS warning**, confirming the certificate is accepted
without validation. From there the fake daemon can answer any RPC call.

## 5. Remediation

Enable real peer verification on the HTTPS path:

- Set the client to verify the peer certificate against a trusted CA store (`SSL_VERIFY_PEER`),
- Enforce hostname matching against the configured daemon address,
- Reject expired / not-yet-valid certificates,
- For self-hosted / self-signed daemons, support explicit certificate or public-key **pinning**
  configured out-of-band, rather than accepting any certificate by default.

## 6. Disclosure outcome

Zano confirmed the certificate-validation logic is incomplete. They downgraded High→Low on the
grounds that exploitation presupposes a hostile-network position, then confirmed and paid
**1000 USDC** (tx `0x4b8c...c650`).
