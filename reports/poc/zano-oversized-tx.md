# PoC notes — Zano tx_pool unbounded-transaction resource exhaustion (Immunefi #50239)

## Goal

Show that `tx_memory_pool::add_tx` admits a transaction with no early bound on size /
input count / output count / Zarcanum proof complexity, so a single oversized transaction forces
disproportionate validation work and degrades the node.

## Steps

1. Build and run a testnet node:
   ```
   git clone https://github.com/hyle-team/zano.git
   cd zano
   make -j"$(nproc)"
   ./build/release/src/zanod --testnet
   ```

2. Construct an oversized transaction:
   - Prepare a tx with **200+ inputs and 200+ outputs**.
   - Enable **Zarcanum** output mode (so validation must verify many Pedersen commitments and
     range/surjection proofs).
   - Assemble the serialized `tx_as_hex`.

3. Submit via RPC:
   ```
   curl -X POST http://127.0.0.1:<rpc-port>/json_rpc \
     -H "Content-Type: application/json" \
     -d '{"method": "send_raw_tx", "params": {"tx_as_hex": "<oversized_tx_hex>"}}'
   ```

## Expected observation

- Node CPU usage spikes (>30% over baseline in testing) while verifying the oversized proofs.
- Responsiveness to normal transactions/RPC drops (verification bottleneck in the pool).
- Repeated submissions compound mempool load and risk overflow on lower-spec nodes.

## Measurement

Sample CPU before/during with `top -p $(pgrep zanod)` (or `pidstat -p $(pgrep zanod) 1`) across
the preceding-24h-style baseline vs. the attack window to substantiate the ≥30% resource-increase
impact category.

## Fix direction

Enforce early, cheap rejection bounds in `add_tx` (and its callers) on total tx size, input
count, output count, and proof element counts before running expensive cryptographic
verification — the pricing side of which the project is addressing under its "Dynamic fee
implementation" roadmap milestone.
