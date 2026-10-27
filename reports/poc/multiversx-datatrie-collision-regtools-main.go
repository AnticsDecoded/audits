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
