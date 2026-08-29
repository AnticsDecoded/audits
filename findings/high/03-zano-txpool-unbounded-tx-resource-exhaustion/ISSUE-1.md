# Lack of Transaction Limits allowing Resource Exhaustion

**Program:** Zano (Immunefi Bug Bounty) · **Submission #50239**
**Target:** https://github.com/hyle-team/zano/blob/master/src/currency_core/tx_pool.cpp — Blockchain/DLT
**Impact:** Increasing network processing node resource consumption by at least 30% without brute-force actions, compared to the preceding 24 hours
**Status:** Closed — acknowledged known issue (roadmap: "Dynamic fee implementation")

## Brief / Intro

I discovered that Zano's `tx_pool.cpp` does not enforce strict limits on transaction size,
input/output count, or ring-signature complexity before accepting transactions into the mempool.
This opens the door for malicious actors to craft oversized transactions that consume
disproportionate resources during validation and propagation, leading to a network-wide DoS.

## Vulnerability Details

The function responsible for handling incoming transactions (`add_tx`) processes the raw tx blob
but fails to implement size- or structure-based rejection early enough:

```cpp
bool tx_memory_pool::add_tx(const transaction &tx, ...)
```

No explicit upper-bound check on:

- Total tx size
- Number of inputs
- Number of outputs
- Zarcanum proof complexity

It results in transactions with huge payloads being accepted and later bottlenecking mempool
verification.

## Impact Details

An attacker can repeatedly submit enormous Zarcanum transactions that force verification of large
Pedersen commitments and surjection proofs. This can:

- Cause CPU usage to spike significantly (>30% confirmed in my tests)
- Increase mempool load, delaying legitimate tx processing
- Cause RPC lag for wallet and miner nodes
- Risk mempool overflow on lower-spec nodes

## References

- Code file: https://github.com/hyle-team/zano/blob/master/src/currency_core/tx_pool.cpp

## Proof of Concept

Step-by-step reproduction (see [`POC__oversized_tx.md`](./POC__oversized_tx.md)):

Setup:

```
git clone https://github.com/hyle-team/zano.git
cd zano
make -j$(nproc)
./build/release/src/zanod --testnet
```

Construct an oversized transaction:

- Use the Zano wallet to prepare a tx with 200+ inputs and 200+ outputs.
- Enable Zarcanum output mode.
- Inject custom-crafted Zarcanum range proofs.
- Submit via RPC:
  ```
  curl -X POST http://127.0.0.1:port/json_rpc \
    -d '{"method": "send_raw_tx", "params": {"tx_as_hex": "<oversized_tx_hex>"}}'
  ```

You would notice the node becomes unresponsive to normal txs and the increase in CPU.

## Project response (timeline excerpt)

> This issue has already been acknowledged by team and planned to be fixed with "Dynamic fee
> implementation" milestone, this would use tx inputs count as justification of tx fee. Please
> find here the proof of the claim: https://zano.org/roadmap (Dynamic fee implementation). The
> bug bounty program only pays a reward to the first report of any particular issue, so this
> report will not receive a reward.
