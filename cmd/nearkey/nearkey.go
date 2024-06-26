// nearkey generates a near node/account/validator key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

const (
	prefix       = "ed25519:"
	alphabet     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	alphabetIdx0 = '1'
)

var bigRadix = big.NewInt(58)
var bigZero = big.NewInt(0)

// encode encodes a byte slice to a modified base58 string. Lifted from github.com/btcsuite/btcd/btcutil/base58.
func encode58(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, alphabet[mod.Int64()])
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}

type KeyFile struct {
	AccountID string
	PublicKey string
	SecretKey string
}

func (kf *KeyFile) MarshalJSON() ([]byte, error) {
	type sk struct {
		AccountID string `json:"account_id"`
		PublicKey string `json:"public_key"`
		SecretKey string `json:"secret_key"`
	}
	return json.Marshal(sk(*kf))
}

type PrivateKeyFile KeyFile

func (kf *PrivateKeyFile) MarshalJSON() ([]byte, error) {
	type pk struct {
		AccountID string `json:"account_id"`
		PublicKey string `json:"public_key"`
		SecretKey string `json:"private_key"`
	}
	return json.Marshal(pk(*kf))
}

func newKey(accountid string, private bool) string {
	var d []byte
	var err error
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err) // This should never occur.
	}
	kf := &KeyFile{
		AccountID: accountid,
		PublicKey: prefix + encode58(pub),
		SecretKey: prefix + encode58(priv),
	}
	if private {
		d, err = json.MarshalIndent((*PrivateKeyFile)(kf), "", "  ")
	} else {
		d, err = json.MarshalIndent(kf, "", "  ")
	}
	if err != nil {
		panic(err) // This should never occur.
	}
	return string(d)
}

func randID() string {
	d := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, d); err != nil {
		panic(err) // Should never happen
	}
	return hex.EncodeToString(d)
}

func addRandToAccountID(accountid string) string {
	return strings.Replace(accountid, "%", randID(), 1)
}

var (
	privateFormat bool = false
)

func init() {
	flag.BoolVar(&privateFormat, "p", false, "generate private format instead of secret format")
}

func main() {
	flag.Parse()
	var accountID string
	if len(flag.Args()) > 0 {
		accountID = addRandToAccountID(flag.Args()[0])
	}
	fmt.Fprint(os.Stdout, newKey(accountID, privateFormat))
	os.Exit(0)
}
