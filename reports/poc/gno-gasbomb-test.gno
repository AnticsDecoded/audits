package gasbomb

import "testing"

func TestBombQ(t *testing.T) {
	// tiny sizes: correctness only (IsValid returns false, no panic, loop completes)
	if got := BombQ(4096, 3); got != 3 {
		t.Fatalf("BombQ iterations = %d, want 3", got)
	}
}
