// nearcall allows to send large encoded arguments to a contract method.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/aurora-is-near/near-api-go"
	"github.com/btcsuite/btcutil/base58"
	"github.com/davecgh/go-spew/spew"
)

var (
	network    = "testnet"
	inputFile  = "contractCode.wasm"
	receiver   = "contractOwner.testnet"
	contractID = "contractid.testnet"
	method     = "contract.method"
)

func GoCall(network, accountID, contract, method, argfile string) (string, interface{}, error) {
	args, err := ioutil.ReadFile(argfile)
	if err != nil {
		return "", nil, err
	}
	h := sha256.New()
	h.Write(args)
	hs := h.Sum(nil)
	arghash := base58.Encode(hs)
	nodeURL := fmt.Sprintf("https://rpc.%s.near.org", network)
	conn := near.NewConnection(nodeURL)
	config := &near.Config{
		NodeURL:   nodeURL,
		NetworkID: network,
	}
	account, err := near.LoadAccount(conn, config, accountID)
	if err != nil {
		return arghash, nil, err
	}
	resp, err := account.FunctionCall(contract, method, args, 100_000_000_000_000, *(big.NewInt(0)))
	if err != nil {
		return arghash, nil, err
	}
	return arghash, resp["status"], nil
}

func init() {
	flag.StringVar(&network, "network", "testnet", "NEAR network to use (testnet, mainnet, ...)")
	flag.StringVar(&receiver, "account", "", "AccountID of called")
	flag.StringVar(&contractID, "contract", "", "Contract to call")
	flag.StringVar(&method, "method", "store", "Contract method to call")
	flag.StringVar(&inputFile, "args", "", "File containing call argument(s)")
}

func main() {
	flag.Parse()
	if network == "" || receiver == "" || contractID == "" || method == "" || inputFile == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Missing parameters\n")
		os.Exit(1)
	}
	argHash, res, err := GoCall(network, receiver, contractID, method, inputFile)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Argument hash: %s\n", argHash)
	spew.Dump(res)
	os.Exit(0)
}
