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
