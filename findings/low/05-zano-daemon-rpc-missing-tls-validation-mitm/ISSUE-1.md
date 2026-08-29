# Missing TLS Certificate Validation on Daemon RPC Connection Leads to Sensitive Data Exposure via MITM

**Target:** https://github.com/hyle-team/zano/blob/master/src/wallet/core_default_rpc_proxy.cpp — Websites & Apps
**Impact:** Improperly disclosing confidential user information

## Brief / Intro

Zano's wallet connects to a daemon backend over HTTP or HTTPS using the
`core_default_rpc_proxy.cpp` interface. However, when connecting over HTTPS, the application does
not validate the TLS certificate of the remote daemon. As a result, an attacker can perform a
man-in-the-middle (MITM) attack using a self-signed or forged certificate and intercept or modify
sensitive RPC data. This exposes wallet activity, transaction metadata, and alias queries, posing
a serious privacy and integrity threat.

## Vulnerability Details

The vulnerability lies in the following logic from `core_default_rpc_proxy.cpp`:

```cpp
if (u.schema == "https") {
    m_http_client.set_is_ssl(true);
}
```

This enables SSL mode but does not validate the identity of the TLS certificate. There's no
verification of:

- The certificate's authenticity
- The issuer (CA)
- Hostname matching
- Expiration

Any server with a TLS listener can impersonate a daemon. If a wallet user is tricked into
connecting to a malicious daemon (via DNS spoofing, local network, or other means), Zano will
accept the connection without complaint and expose all RPC traffic to the attacker.

## Impact Details

By exploiting, an attacker can:

- Intercept and read wallet-to-daemon communication
- Log or modify RPC calls such as `/getblocktemplate`, `/sendrawtransaction`, `/getaliases`,
  `/getinfo`
- Serve fake sync states or block templates
- Pass poisoned alias or transaction data

## References

- Vulnerable source: https://github.com/hyle-team/zano/blob/master/src/wallet/core_default_rpc_proxy.cpp

## Proof of Concept

Man-in-the-Middle (MITM) via self-signed HTTPS daemon. I exploit the lack of certificate
validation in the Zano wallet by standing up a malicious HTTPS daemon with a self-signed
certificate, and proving the wallet connects without warnings. See
[`POC__fake_https_daemon.sh`](./POC__fake_https_daemon.sh) for the runnable steps.

Step by step:

1. Create a self-signed TLS certificate:
   ```
   openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 \
     -subj "/CN=fake.zano-daemon.com"
   ```
2. Serve a fake HTTPS daemon:
   ```
   mkdir fake_daemon
   echo '{"status": "OK", "info": "Fake Daemon Connected"}' > fake_daemon/index.html
   python3 -m http.server 8081 --directory ./fake_daemon --bind 127.0.0.1 \
     --certfile cert.pem --keyfile key.pem
   ```
3. Configure the wallet to connect to the fake daemon:
   ```json
   { "daemon_address": "https://127.0.0.1:8081" }
   ```
4. Launch the wallet and let it connect.

**Result:** Zano connects to the fake daemon, no TLS warnings or errors are shown, the
self-signed certificate is silently accepted, and all wallet RPC traffic is sent to the
malicious server — where it can be inspected, modified, or answered with injected RPC responses
(fake sync height, injected aliases, logged broadcast attempts).
