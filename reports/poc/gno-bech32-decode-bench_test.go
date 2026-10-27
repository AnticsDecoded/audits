package gnosec

import (
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

func benchSize(b *testing.B, n int) {
	// charset-valid, checksum-invalid string of length n ("g1" + 'q'*k)
	s := "g1" + strings.Repeat("q", n-2)
	b.ResetTimer()
	t0 := time.Now()
	for i := 0; i < b.N; i++ {
		_, _, err := bech32.DecodeNoLimit(s)
		if err == nil {
			b.Fatal("expected error")
		}
	}
	d := time.Since(t0)
	b.ReportMetric(float64(d.Nanoseconds())/float64(b.N)/float64(n), "ns/byte")
	b.ReportMetric(float64(d.Milliseconds())/float64(b.N), "ms/call")
}

func BenchmarkDecode4KB(b *testing.B)   { benchSize(b, 4<<10) }
func BenchmarkDecode64KB(b *testing.B)  { benchSize(b, 64<<10) }
func BenchmarkDecode1MB(b *testing.B)   { benchSize(b, 1<<20) }
func BenchmarkDecode8MB(b *testing.B)   { benchSize(b, 8<<20) }
func BenchmarkDecode32MB(b *testing.B)  { benchSize(b, 32<<20) }
func BenchmarkDecode64MB(b *testing.B)  { benchSize(b, 64<<20) }
