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
