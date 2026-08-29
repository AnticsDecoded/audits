## PirateNetwork/pirate
Private audit · Target: [PirateNetwork/pirate](https://github.com/PirateNetwork/pirate)

Pirate (`pirated`) is a privacy-focused, fully-shielded Komodo/Zcash-derived L1 daemon (Sapling,
Equihash PoW, Komodo asset-chain framework). Both findings below are reachable over unauthenticated
peer-to-peer messages after a normal P2P handshake — no RPC/admin/wallet permission is required.

- **Audited commit:** `09e7f5088e6771d5c2c4aec734af5663adbdbadd`
- **Affected refs:** `origin/master`, `origin/dev`, `origin/dev-consolidation`, `origin/thread-lock-logging`, `v5.8.2`, `v5.9.0`, `v5.9.2`, `v6.0.0-beta4`, `v6.0.0-RC1` · **Patched:** none known at time of report
- **PoC harness:** [`poc/pirate-running-e2e.py`](./poc/pirate-running-e2e.py)

**Classification caveat.** Both issues are confirmed as node-availability / sync-state denial-of-service
issues. Neither is proven as on-chain inflation, invalid full-block acceptance, or accepted-invalid-
transaction-in-block. Strict `-regtest -ac_name=PIRATE` does not confirm on-chain exploitation of the
coin-import crash because regtest disables standardness (`fRequireStandard = false`) and the safer
coin-import verifier rejects the malformed payload before the vulnerable standardness path is reached.
No exact public duplicate was found for either issue.

---

### [High-01] Empty coin-import push in an unauthenticated P2P tx crashes a synced production-mode node

**Target:** `src/script/script.cpp` (`CScript::IsCoinImport()`), reached via `src/main.cpp` (`AreInputsStandard()` → `AcceptToMemoryPool()`)

**Weakness:** CWE-125 (out-of-bounds read) / CWE-20 (improper input validation)
**Severity:** High · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Finding description and impact**

An unauthenticated peer can crash a synced production-mode Pirate node during transaction relay by
sending a malformed coin-import-shaped transaction whose `scriptSig` is an empty push
(`OP_PUSHDATA1 0x00`). The transaction is classified as a coin import because
`vin[0].prevout.n == 1000000000`, and the mempool standardness path calls `CScript::IsCoinImport()`
*before* the safer `VerifyCoinImport()` validator. `CScript::IsCoinImport()` dereferences
`data.begin()[0]` without checking that the pushed byte vector is non-empty, causing a process crash.

The transaction-level classifier checks only the input shape:

```cpp
// src/primitives/transaction.h
bool IsCoinImport() const
{
    return (vin.size() == 1 && vin[0].prevout.n == 10e8);
}
```

For a one-input transaction with `prevout.n == 1000000000`, mempool admission reaches the
standardness gate, which special-cases import-shaped transactions and calls the script-level parser:

```cpp
// src/main.cpp
if (Params().RequireStandard() && !AreInputsStandard(tx, view, consensusBranchId))
    return error("AcceptToMemoryPool: reject nonstandard transaction input");

// AreInputsStandard()
if (tx.IsCoinImport())
    return tx.vin[0].scriptSig.IsCoinImport();
```

The vulnerable parser assumes every push opcode carries at least one pushed byte:

```cpp
// src/script/script.cpp
bool CScript::IsCoinImport() const
{
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (this->GetOp(pc, opcode, data))
        if (opcode > OP_0 && opcode <= OP_PUSHDATA4)
            return data.begin()[0] == EVAL_IMPORTCOIN;   // data may be empty
    return false;
}
```

An empty push satisfies `opcode > OP_0 && opcode <= OP_PUSHDATA4` but leaves `data` empty.
Dereferencing `data.begin()[0]` is undefined behavior and crashed the tested daemon with `SIGSEGV`.
The dedicated verifier `VerifyCoinImport()` (`src/importcoin.cpp`) handles this input correctly —
it explicitly rejects `evalScript.size() == 0` before indexing — so the bug is an ordering / unsafe-
parser issue: mempool standardness reaches the unsafe parser before the robust import verifier runs.

**Conditions for exploitation**

- `Params().RequireStandard()` is true (mainnet/testnet; false in regtest), and
- the node is out of initial block download — P2P `tx` processing returns early during IBD
  (`if (IsInitialBlockDownload()) return true;`).

That is the normal state of a synced production node. The confirmed route is P2P relay, not RPC.

**Proof of Concept**

See [`poc/pirate-running-e2e.py`](./poc/pirate-running-e2e.py) (`make_coin_import_empty_push_tx`). The
crash transaction is a Sapling v4 tx with one input (`prevout.n = 1000000000`,
`scriptSig = OP_PUSHDATA1 0x00`) and one zero-value `OP_RETURN` output:

```text
0400008085202f8901010000000000000000000000000000000000000000000000000000000000000000ca9a3b024c00ffffffff010000000000000000016a01000000000000000000000000000000000000
```

Observed running-daemon results:

```text
coin-regtest  (-regtest -ac_name=PIRATE):
  RPC sendrawtransaction -> "invalid-coin-import"; P2P tx received; daemon stayed alive.
  (regtest disables standardness, so the payload reaches VerifyCoinImport() and is rejected.)

coin-local-prod  (-ac_name=LOCALARRR, production-style, node left IBD):
  "Leaving InitialBlockDownload (latching to false)"
  P2P handshake completed (protocol 170013); "received: tx (82 bytes) peer=1"
  process exited with return code -11  (SIGSEGV)
```

Two `EXPECT_DEATH` unit tests (`Mempool.CoinImportEmptyPushCrashesInputStandardness` and
`Mempool.CoinImportEmptyPushCrashesAcceptToMemoryPool`) model the unsafe path through
`AreInputsStandard()` and `AcceptToMemoryPool()` respectively and both pass under
`--gtest_death_test_style=threadsafe`.

**Impact**

Remote unauthenticated node denial of service. Any peer able to open a normal P2P connection to a
synced node can crash the process under production-style standardness. Affected parties: public
full-node operators, exchanges/service providers running synced infrastructure, and lite-wallet
backends depending on stable full nodes. Not confirmed as invalid on-chain tx/block acceptance or
inflation.

**Recommended mitigation steps**

Bounds-check the push before indexing:

```cpp
bool CScript::IsCoinImport() const
{
    const_iterator pc = this->begin();
    vector<unsigned char> data;
    opcodetype opcode;
    if (this->GetOp(pc, opcode, data))
        if (opcode > OP_0 && opcode <= OP_PUSHDATA4)
            return !data.empty() && data[0] == EVAL_IMPORTCOIN;
    return false;
}
```

Additional hardening: reject malformed import-shaped transactions in
`CheckTransactionWithoutProofVerification()`; route import-shaped checks through `VerifyCoinImport()`
before ad hoc standardness parsing; add a non-death regression test asserting the malformed empty-push
import is rejected without crashing.

---

### [High-02] Unauthenticated P2P headers with invalid PoW are accepted as header-only best chain state

**Target:** `src/main.cpp` (`AcceptBlockHeader()` calling `CheckBlockHeader(..., fCheckPOW=0)`, `ContextualCheckBlockHeader()`)

**Weakness:** CWE-345 (insufficient verification of data authenticity) / CWE-20 (improper input validation)
**Severity:** High · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

**Finding description and impact**

An unauthenticated peer can send a chain of block headers that have no valid Equihash solution and do
not satisfy full proof-of-work validation, yet the node accepts and indexes them as valid header-tree
state. `AcceptBlockHeader()` calls `CheckBlockHeader(..., fCheckPOW=0)`, which skips Equihash
validation; `ContextualCheckBlockHeader()` checks timestamps, difficulty bits, checkpoints, and
version, but not the actual header solution/hash target. The invalid headers are added to
`mapBlockIndex`, marked `BLOCK_VALID_TREE`, and can be promoted to `pindexBestHeader`.

```cpp
// src/main.cpp — CheckBlockHeader() only checks Equihash when fCheckPOW is set
if ( fCheckPOW ) {
    if ( !CheckEquihashSolution(&blockhdr, Params()) )
        return state.DoS(100, error("CheckBlockHeader(): Equihash solution invalid"),
                         REJECT_INVALID, "invalid-solution");
}

// AcceptBlockHeader() passes 0 for fCheckPOW
if (!CheckBlockHeader(futureblockp, *ppindex!=0?(*ppindex)->nHeight:0, *ppindex, block, state, 0)) { ... }
...
if (!ContextualCheckBlockHeader(block, state, pindexPrev)) { ... return false; }
if (pindex == NULL) {
    if ( (pindex = AddToBlockIndex(block)) != 0 ) { ... }
}
```

`ContextualCheckBlockHeader()` validates `nBits`, median-time-past, future-time bound, and
`nVersion` — none of which repair the missing PoW/solution check. Full block validation later rejects
the very same block with `high-hash` once `fCheckPOW` is enabled (via `CheckProofOfWork()` /
`komodo_checkPOW()`), producing an inconsistent state where headers that can never connect as valid
full blocks are still accepted and promoted as best header chain state.

The current code even preserves an upstream comment claiming the header is checked "particularly PoW"
while the actual `AcceptBlockHeader()` call disables the check — the opposite of the historical
"Check block header before accepting it." fix.

**Conditions for exploitation**

- Standard `headers` P2P processing path; regtest confirmed. Headers extend the node's current tip,
  copy the expected difficulty bits, set valid relative timestamps, and leave the Equihash solution
  empty.

**Proof of Concept**

See [`poc/pirate-running-e2e.py`](./poc/pirate-running-e2e.py) (`make_fake_header`, `send_fake_headers`).
Observed running-daemon result under `-regtest`:

```text
headers-regtest:
  Before P2P headers: blocks=0  headers=0
  Sent: 3 fake headers with empty Equihash solutions over a normal P2P `headers` message
  After  P2P headers: blocks=0  headers=3
  getchaintips: height-3 headers-only branch present
    (2b95d20381bcc65d067cf7b8b24bb90ccc2775b8e9f7ba4b508115d6d0a1ed68)
```

The active chain block height stayed at `0`, confirming sync-state / header-state poisoning rather
than invalid full-block acceptance. Unit test `test_block.InvalidPoWHeaderIsAcceptedAsBestHeader`
constructs a block whose PoW is deliberately broken (`CheckProofOfWork()` false), feeds it and two
descendants through `AcceptBlockHeader()`, and asserts each is `BLOCK_VALID_TREE` and becomes
`pindexBestHeader` (running 3 headers ahead of the active tip), while `CheckBlock(..., fCheckPOW=true)`
rejects the same block with `high-hash`.

**Impact**

Remote unauthenticated header-sync denial of service / state poisoning. A peer can make a node believe
a better header-only branch exists whose blocks can never validate: it wastes peer bandwidth and
block-request effort chasing impossible blocks, pollutes header state with invalid work claims, pushes
`pindexBestHeader` ahead of the active tip, and can affect sync-state checks such as `IsNotInSync()`.
Not a demonstrated accepted-invalid-block exploit — full block validation still rejects the block with
`high-hash`.

**Recommended mitigation steps**

- Validate the Equihash solution and full PoW target inside `AcceptBlockHeader()` for peer-supplied
  headers before `AddToBlockIndex()`.
- Alternatively, do not mark/promote headers to `BLOCK_VALID_TREE` / `pindexBestHeader` until PoW and
  Equihash are validated.
- If a full block later fails PoW validation, mark the corresponding header/index invalid so it stops
  being treated as best known header state.
- Add a regression test asserting invalid-PoW headers through `AcceptBlockHeader()` are rejected or not
  promoted.
