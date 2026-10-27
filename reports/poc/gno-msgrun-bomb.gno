package main

func main() {
	s := "g1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	for i := 0; i < 18; i++ { // 32 << 18 = 8 MiB
		s = s + s
	}
	n := 0
	for i := 0; i < 100; i++ {
		a := address(s)
		if a.IsValid() {
			panic("unexpectedly valid")
		}
		n++
	}
	_ = n
}
