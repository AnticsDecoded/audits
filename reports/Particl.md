## particl/particl-core
Private audit · Target: [particl/particl-core](https://github.com/particl/particl-core)

Particl Core (`particld` / `particl-qt`) is a privacy-focused Bitcoin-derived L1 with a RingCT
("anon") confidential-transaction layer. This finding is a consensus-path out-of-bounds read: an
anon (RingCT) input whose witness stack is empty is not rejected by any validation step that runs
before `Consensus::CheckTxInputs`, so the function dereferences a garbage reference and the process
dies with `SIGSEGV`. It is reachable over unauthenticated peer-to-peer transaction relay — no RPC,
wallet, stake, or peer permission is required — and, via a staked block, over block validation on
every node in the network.

- **Audited ref:** `master` (27.99.1.0)
- **Crash site:** [`src/consensus/tx_verify.cpp:238-239`](https://github.com/particl/particl-core/blob/master/src/consensus/tx_verify.cpp#L238-L239) (`Consensus::CheckTxInputs`)
- **Weakness:** CWE-125 (out-of-bounds read) / CWE-20 (improper input validation)
- **Introduced:** 2021 — commits `186c543b73d` ("Consensus params") and `6b5bce49b16` ("…Check for duplicate keyimages in CheckTxInputs"); no bounds check was ever present and later removed.
- **Patched:** none known at time of report
- **Disclosure channel:** `core@particl.io` (`SECURITY.md`, optionally PGP to `0F7C 8778 254F 2E28 2644 2BAC 52D9 8BD1 59DF AF40`). Particl runs no bug-bounty program (no Immunefi/HackerOne, no published scope or tiers, no GitHub security advisories).
- **PoC:** [`poc/particl-anon-witness-oob-checktxinputs.cpp`](./poc/particl-anon-witness-oob-checktxinputs.cpp)

**Severity — researcher analysis.** This report has not been through a vendor triage, so the severity
below is the researcher's analysis rather than a vendor-awarded tier. It is calibrated against this
repository's own precedents. The unauthenticated **mempool path**, taken alone, is a single-node
remote crash with no self-propagation and maps to **Medium** — it is the same bug class, reachability,
and CVSS as the Pirate coin-import crash ([Pirate Medium-01](./Pirate.md), base
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5). The **block-connection path** raises the ceiling:
a staker who embeds the transaction in an otherwise-valid PoS block crashes *every* node that
validates the block — including nodes the attacker is not connected to — which is a network-wide
availability / chain-stall class matching the repository's High tier. The overall rating is driven by
that systemic vector.

**Classification caveat.** This is an out-of-bounds *read* → segfault. There is no sign of memory
disclosure or code execution; the demonstrated outcome is process termination (availability only,
`A:H`, `C:N/I:N`). The block-connection path is real but gated behind producing a valid PoS block
(`CheckProofOfStake`); the mempool path is fully unauthenticated but crashes inside `PreChecks`
*before* the transaction is added to the mempool or relayed, so it does not self-propagate — the
attacker delivers it to each victim directly.

---

### [High-01] Out-of-bounds read on an unchecked anon-input witness stack in `CheckTxInputs` leads to a remote, unauthenticated node crash (DoS)

**Target:** [`src/consensus/tx_verify.cpp:238-239`](https://github.com/particl/particl-core/blob/master/src/consensus/tx_verify.cpp#L238-L239) (`Consensus::CheckTxInputs`)
**Weakness:** CWE-125 (out-of-bounds read) / CWE-20 (improper input validation)
**Severity:** High (researcher analysis) — driven by the network-wide block-connection vector. Unauthenticated mempool vector alone: Medium · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5)

#### Brief / intro

`CheckTxInputs` reads the first element of an anon (RingCT) input's `scriptData.stack` and
`scriptWitness.stack` without first checking either vector is non-empty. An attacker can serialize a
Particl transaction whose anon input carries an empty `scriptWitness.stack`, and it passes every
validation step that runs before `CheckTxInputs`. When execution reaches the read, the node
dereferences a garbage reference and dies with `SIGSEGV`. Anon relay is on by default, so any
unauthenticated peer can send such a transaction to a default, fully-synced mainnet node and crash it;
a staker can put the same transaction in a block and crash every node that validates it.

#### Finding description and impact

The moment `CheckTxInputs` sees an anon input, it binds references to `stack[0]` of two
attacker-controlled vectors — with no check that either has any elements:

```cpp
// src/consensus/tx_verify.cpp:232-239
for (unsigned int i = 0; i < tx.vin.size(); i++)
{
    if (tx.vin[i].IsAnonInput()) {
        state.m_has_anon_input = true;
        nRingCTInputs++;

        const std::vector<uint8_t> &vKeyImages = tx.vin[i].scriptData.stack[0];    // line 238
        const std::vector<uint8_t> &vMI        = tx.vin[i].scriptWitness.stack[0]; // line 239
```

On an empty vector, `operator[](0)` is undefined behavior — it returns a reference built from a garbage
internal pointer. Nothing crashes on that line; it crashes when the reference is actually used, a bit
further down the same anon branch:

```cpp
uint32_t nInputs, nRingSize;
tx.vin[i].GetAnonInfo(nInputs, nRingSize);   // both decoded from prevout.hash — attacker-controlled
if (nInputs < 1 || nInputs > ...) { return state.Invalid(..., "bad-anon-num-inputs"); }
if (nRingSize < ... || nRingSize > ...) { return state.Invalid(..., "bad-anon-ringsize"); }
...
for (size_t k = 0; k < nInputs; ++k) {
    const CCmpPubKey &ki = *((CCmpPubKey*)&vKeyImages[k*33]);   // reads vKeyImages (empty scriptData case)
    ...
    for (size_t i = 0; i < nRingSize; ++i) {
        if (0 != part::GetVarInt(vMI, ofs, (uint64_t&)nIndex, nB)) { ... }   // reads vMI (empty scriptWitness case)
```

`nInputs` and `nRingSize` come out of `prevout.hash` via `GetAnonInfo`
(`src/primitives/transaction.h:235`), so they're fully attacker-controlled. The attacker just sets
in-range values, the loop runs, and the garbage reference gets dereferenced.

**Why the stacks can be empty when we get here.** Nothing on the wire enforces a minimum size on
either stack. `scriptData.stack` is only gated on `IsAnonInput()`:

```cpp
// src/primitives/transaction.h:201-206
SERIALIZE_METHODS(CTxIn, obj) {
    READWRITE(obj.prevout, obj.scriptSig, obj.nSequence);
    if (obj.IsAnonInput()) {
        READWRITE(obj.scriptData.stack);   // compact-size count + N vectors; a count of 0 is legal
    }
}
```

`scriptWitness.stack` is read at the transaction level in `UnserializeTransaction`
(`src/primitives/transaction.h:771`, `:804`), again with no minimum. And `IsAnonInput()` is decided
purely by `prevout.n == 0xffffffa0` (`src/primitives/transaction.h:99,125-128`) — it doesn't look at
the stacks at all. So an anon input with `scriptData.stack` of size 1 and `scriptWitness.stack` of
size 0 deserializes cleanly.

**Nothing upstream catches it.** Every validation step that runs before `CheckTxInputs` fails to
reject the empty-witness case:

| Stage | Where | Checks the anon stacks? |
|---|---|---|
| `CheckTransaction` | `tx_verify.cpp:660` | No — validates outputs, and explicitly skips anon inputs in the duplicate-input and null-prevout checks. |
| `IsStandardTx` | `policy.cpp:106` | No — only inspects `scriptSig` and output scripts; an anon input's empty `scriptSig` passes. |
| `CheckAnonInputMempoolConflicts` | `anon.cpp:28` | Checks `scriptData.stack.size() != 1` (`bad-anonin-dstack-size`) — but not `scriptWitness.stack`. |
| **`CheckTxInputs`** | **`tx_verify.cpp:238-239`** | **crash here** |
| `AreInputsStandard` | `validation.cpp:1007` | runs after the crash |
| `IsWitnessStandard` | `policy.cpp:308` | runs after the crash — and only bounds the stack from above (`> 3`), so an empty stack would pass anyway |
| `VerifyMLSAG` | `anon.cpp:122-127` | Has the correct check (`bad-anonin-wstack-size`, `scriptWitness.stack.size() != 2`), but it's reached from `CheckInputScripts` in `PolicyScriptChecks`/`ConsensusScriptChecks` — i.e. after `CheckTxInputs`. Never runs. |

The right guard already lives in the codebase — `VerifyMLSAG` rejects `scriptWitness.stack.size() != 2`
with `bad-anonin-wstack-size`. It just runs later than `CheckTxInputs`. So this isn't "handled
elsewhere by design"; it's a real gap in the earlier consensus function.

**Two ways to reach it.**

1. *Mempool.* `MemPoolAccept::PreChecks` (`validation.cpp:841`) runs `CheckTransaction` (861) →
   `IsStandardTx` (875) → `CheckAnonInputMempoolConflicts` (904) → `CheckTxInputs` (1003). Because
   `CheckAnonInputMempoolConflicts` rejects an empty `scriptData` stack but not an empty
   `scriptWitness` stack, the shape that gets through is a valid `scriptData.stack` (size 1, 33-byte
   key image) with an empty `scriptWitness.stack` — it crashes at the `vMI` read
   (`GetVarInt(vMI, ...)`).
2. *Block connection.* `ConnectBlock` (`validation.cpp:3024`) calls `CheckTxInputs` directly with no
   `CheckAnonInputMempoolConflicts` in front. Here both variants crash — empty `scriptData`
   (line 238 → `&vKeyImages[k*33]`) and empty `scriptWitness` (line 239). Gated by
   `CheckProofOfStake`, so it needs a valid staked block.

**The anon freeze doesn't prevent this.** Particl froze pre-fork blinded/anon outputs after the
Feb-2021 inflation incident (`m_frozen_anon_index = 27340`, `m_frozen_blinded_height = 884433`,
`exploit_fix_2_height = 976263`; `src/kernel/chainparams.cpp:530-540`). But every freeze/blacklist
check works on ring-member indices decoded *from* `vMI`, so they all run *after* the unguarded reads
on lines 238-239 (the `if (nIndex <= ...m_frozen_anon_index)` check is inside the ring loop). The
freeze limits which outputs an anon input can reference; it doesn't reject the input first. Same with
`-acceptanontxn` — its check is inside `VerifyMLSAG` (`anon.cpp:68-70`, `tx_verify.cpp:470`), which
runs after the crash, and it defaults to on anyway (`DEFAULT_ACCEPT_ANON_TX = true`,
`src/validation.h:1349`).

#### Impact

Remote, unauthenticated denial of service — a full-node crash (`particld` / `particl-qt`). No wallet,
funds, stake, credentials, RPC access, or peer permissions are needed for the mempool path.

- **Mempool path (remote, unauthenticated):** one malformed transaction crashes a default,
  fully-synced mainnet node. Inbound connections are accepted by default and anon relay is on by
  default, so an attacker just delivers the transaction. One caveat worth being upfront about: the
  crash happens inside `PreChecks`, *before* the transaction is added to the mempool or relayed
  (`validation.cpp:1400-1439`), so the node dies before forwarding it. There's no self-propagation —
  the attacker has to send it to each victim directly. Cheap at scale, but not a worm.
- **Block-connection path (needs stake):** a staker who includes the transaction in an
  otherwise-valid PoS block crashes every node that validates the block, including ones the attacker
  isn't connected to. This is the higher-impact vector — it can stall or partition the network — but
  it costs a valid staked block (`CheckProofOfStake`, `validation.cpp:2822`).
- **Availability only:** this is an out-of-bounds *read* → segfault. No sign of memory disclosure or
  code execution; the practical outcome is the process terminating.

**Gating and preconditions.** Nothing meaningful blocks it. `require_standard` is default-on but
doesn't filter it (`IsStandardTx` ignores anon-input stacks), and `-acceptanontxn` defaults to true
with its check running after the crash. Two minor preconditions, neither a real mitigation: (1) the
node must be fully synced — while it's behind its peers, `PreChecks` short-circuits anon transactions
with `state.Error("Syncing")` (`validation.cpp:969-974`, gated on `-checkpeerheight`, default true),
and basically every production node is synced; (2) the block path needs a valid PoS block.

Affected parties: public full-node operators, exchanges / service providers running synced
infrastructure, staking nodes, and any wallet backend depending on stable full nodes.

#### Proof of Concept

Full runnable test: [`poc/particl-anon-witness-oob-checktxinputs.cpp`](./poc/particl-anon-witness-oob-checktxinputs.cpp).

A BOOST unit test builds a Particl transaction with one anon input that has a valid 33-byte
`scriptData.stack[0]` and an empty `scriptWitness.stack`, round-trips it through serialization (to
prove the shape survives the wire format), checks it passes `IsStandardTx`/`IsWitnessStandard`, then
calls `CheckTxInputs` in a forked child so the SIGSEGV can be observed without killing the test
runner. Added to `src/test/particlchain_tests.cpp` (+75 lines):

```cpp
BOOST_AUTO_TEST_CASE(anon_input_missing_witness_stack_crashes_checktxinputs)
{
#ifdef WIN32
    BOOST_TEST_MESSAGE("Skipping POSIX crash repro on Windows.");
#else
    CMutableTransaction txn;
    txn.version = PARTICL_TXN_VERSION;

    CTxIn ai;
    ai.prevout.n = COutPoint::ANON_MARKER;
    ai.SetAnonInfo(1, 1);                       // nInputs=1, nRingSize=1
    ai.scriptData.stack.emplace_back(33, 0);    // valid 33-byte key-image blob -> passes bad-anonin-dstack-size
    txn.vin.push_back(ai);                        // scriptWitness.stack left EMPTY

    CAmount zero_fee = 0;
    OUTPUT_PTR<CTxOutData> out_fee = MAKE_OUTPUT<CTxOutData>();
    out_fee->SetCTFee(zero_fee);
    txn.vpout.push_back(out_fee);

    CKey k;
    InsecureNewKey(k, true);
    CScript script_pubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(k.GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    txn.vpout.push_back(MAKE_OUTPUT<CTxOutStandard>(1 * COIN, script_pubkey));

    // Round-trip through the wire format the way a peer would deliver it.
    DataStream ss{};
    ss << TX_WITH_WITNESS(txn);
    CMutableTransaction decoded;
    ss >> TX_WITH_WITNESS(decoded);

    BOOST_REQUIRE_EQUAL(decoded.vin.size(), 1U);
    BOOST_REQUIRE(decoded.vin[0].IsAnonInput());
    BOOST_REQUIRE_EQUAL(decoded.vin[0].scriptData.stack.size(), 1U);
    BOOST_REQUIRE(decoded.vin[0].scriptWitness.stack.empty());   // the malformed condition survives deserialization

    const CTransaction tx_standard(decoded);
    std::string reason;
    // Nothing on the pre-CheckTxInputs path rejects it:
    BOOST_REQUIRE_MESSAGE(IsStandardTx(tx_standard, std::nullopt, true, CFeeRate(3000), reason, GetTime()), reason);
    CCoinsView viewDummyForPolicy;
    CCoinsViewCache inputsForPolicy(&viewDummyForPolicy);
    BOOST_REQUIRE(IsWitnessStandard(tx_standard, inputsForPolicy));

    pid_t pid = fork();
    BOOST_REQUIRE(pid >= 0);
    if (pid == 0) {
        TxValidationState state;
        state.SetStateInfo(GetTime(), 1, Params().GetConsensus(), true, false);
        if (!CheckTransaction(tx_standard, state)) {
            _exit(10);   // would mean CheckTransaction rejected it (it does not)
        }
        CCoinsView viewDummy;
        CCoinsViewCache inputs(&viewDummy);
        CAmount txfee = 0;
        (void)Consensus::CheckTxInputs(tx_standard, state, inputs, 1, txfee);
        _exit(11);       // would mean CheckTxInputs returned normally (it does not)
    }

    int status = 0;
    BOOST_REQUIRE_EQUAL(waitpid(pid, &status, 0), pid);
    BOOST_REQUIRE_MESSAGE(WIFSIGNALED(status),
        "CheckTxInputs returned instead of crashing; child exit status " << WEXITSTATUS(status));
    BOOST_TEST_MESSAGE("CheckTxInputs child terminated with signal " << WTERMSIG(status));
    BOOST_CHECK_EQUAL(WTERMSIG(status), SIGSEGV);
#endif
}
```

What each step confirms:

1. After `ss >> TX_WITH_WITNESS(decoded)`, the input is still an anon input,
   `scriptData.stack.size() == 1`, and `scriptWitness.stack` is empty — the malformed shape is
   representable on the wire.
2. `IsStandardTx` and `IsWitnessStandard` both return true, so `require_standard` (default on mainnet)
   doesn't filter it.
3. The child reaches the `CheckTxInputs` call instead of exiting 10 — so `CheckTransaction` accepted
   it.
4. The child neither returns (exit 11) nor is rejected — it's killed by a signal, asserted to be
   `SIGSEGV`.

**Build / test setup.** Built the whole tree from source in an Ubuntu Docker container (image built
from the host repo), producing a fully-linked `src/test/test_particl` (~651 MB). Host is macOS; the
suite runs in the Linux container. Full build of the codebase with the PoC applied, on Linux — not a
native macOS build.

**Test run (`make -j check`).** Ran to completion with the PoC in place: 139 suites launched, 1
errored. `particlchain_tests` (which holds the PoC) ran and passed — the forked child SIGSEGV'd,
`waitpid` contained it, and the suite finished without taking down the runner (the harness uses
`--catch_system_errors=no`, so the deliberate child crash is fine). The one errored suite was
`validation_chainstatemanager_tests`, 2 failures, both `dbwrapper_error: Fatal LevelDB error:
Corruption: bad block type` in the snapshot/assumeutxo tests. That's pre-existing and unrelated: the
PoC touches only `src/test/particlchain_tests.cpp` (no chainstate/LevelDB code); the errors are
on-disk LevelDB corruption in the test's own temp regtest fixture; and the suite passes in isolation,
failing only under the full parallel run — a parallel-I/O artifact in the container, not a regression.
Being honest: since it's environmental, the full suite can't be called green on this box, but it's
clearly decoupled from this finding.

#### Recommended mitigation steps

Reject malformed anon inputs at the top of the anon branch in `CheckTxInputs`, before any `stack[0]`
read — the same guards already used in `CheckAnonInputMempoolConflicts` and `VerifyMLSAG`:

```cpp
if (tx.vin[i].scriptData.stack.size() != 1) {
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-anonin-dstack-size");
}
if (tx.vin[i].scriptWitness.stack.size() != 2) {
    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-anonin-wstack-size");
}
```

Keep the existing `vKeyImages.size() == nInputs * 33` length check too, and add a unit test asserting
the transaction is now rejected cleanly instead of crashing.

---

### Notes on scope and prior art

Particl has no bug-bounty program — no Immunefi/HackerOne, no published scope or severity tiers, no
GitHub security advisories. The only policy is `SECURITY.md`: report privately to **core@particl.io**,
optionally PGP-encrypted to the Particl Core key
`0F7C 8778 254F 2E28 2644 2BAC 52D9 8BD1 59DF AF40`. DoS/consensus crashes aren't listed either way,
but a consensus-validation crash plainly "directly affects Particl Core," which is the stated bar for
that channel. Expect private coordinated disclosure, not a payout.

No sign this is already known. The reads have been unguarded since 2021 (commits `186c543b73d`
"Consensus params" and `6b5bce49b16` "…Check for duplicate keyimages in CheckTxInputs") — no bounds
check was ever there and later removed. No TODO/FIXME/SECURITY comment mentions it, no committed test
feeds an empty witness stack (existing anon tests in `src/wallet/test/rct_tests.cpp` all use
fully-populated stacks), and nothing in the release notes or CHANGELOG. The matching guard exists only
in `VerifyMLSAG`, which runs later — which is what says the gap is real rather than handled on this
path.

### References

- `src/consensus/tx_verify.cpp:238-239` — the unguarded `stack[0]` reads (crash site)
- `src/consensus/tx_verify.cpp:660` — `CheckTransaction` (no anon-stack guard)
- `src/anon.cpp:28-44` — `CheckAnonInputMempoolConflicts` (guards `scriptData` only)
- `src/anon.cpp:122-127` — `VerifyMLSAG` (the correct guard, incl. `bad-anonin-wstack-size`; runs too late)
- `src/policy/policy.cpp:106,308` — `IsStandardTx` / `IsWitnessStandard`
- `src/validation.cpp:861,875,904,1003,1007,1012,2378-2379,3024` — mempool and block call ordering
- `src/primitives/transaction.h:99,125-128,201-206,235,771,804` — anon marker, serialization, `GetAnonInfo`
- `src/kernel/chainparams.cpp:530-540` — mainnet freeze / exploit-fix parameters
- `src/validation.h:1349`, `src/init.cpp:642` — `DEFAULT_ACCEPT_ANON_TX = true`
