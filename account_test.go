/*
 * @Author: huyongchao huyongchao98@163.com
 * @Date: 2023-04-08 14:16:20
 * @LastEditors: huyongchao huyongchao98@163.com
 * @LastEditTime: 2023-04-08 17:06:57
 * @FilePath: /near-api-go/account_test.go
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
package near

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aurora-is-near/near-api-go/keystore"
	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
)

func buildAccount() Account {
	rpcEndpoint := "https://rpc.testnet.near.org"
	mainAccountID := "testdafa.testnet"

	connection := NewConnectionWithTimeout(rpcEndpoint, time.Second*10)

	keyPair := keystore.Ed25519KeyPair{
		AccountID:      mainAccountID,
		PublicKey:      "ed25519:6wTjVszCPsk6ZGjVNk4tTjHpY2A7AMypfapcWCfo8umZ",
		PrivateKey:     "ed25519:3G7BmuSTuo825Y1kCTyRwMm9incjuNDcf24p42pKi9PgDv3JyvPzJT4Kb88mRHR3KyPDXNu2Gsy3w8dRMAR6eKoM",
		Ed25519PubKey:  base58.Decode("6wTjVszCPsk6ZGjVNk4tTjHpY2A7AMypfapcWCfo8umZ"),
		Ed25519PrivKey: base58.Decode("3G7BmuSTuo825Y1kCTyRwMm9incjuNDcf24p42pKi9PgDv3JyvPzJT4Kb88mRHR3KyPDXNu2Gsy3w8dRMAR6eKoM"),
	}

	a := Account{
		conn: connection,
		kp:   &keyPair,
	}

	a.accessKeyByPublicKeyCache = make(map[string]map[string]interface{})
	return a
}
func TestCreateAccountTransactionWithFunctionCall(t *testing.T) {

	newAccountID := "example-2212.testdafa.testnet"

	a := buildAccount()

	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "报错了")

	pubKey := utils.PublicKeyFromEd25519(pub)

	bigInt := big.NewInt(0)

	result, theErr := a.CreateAccount(newAccountID, pubKey, *bigInt)

	require.NoError(t, theErr, "报错了")

	fmt.Println(result)

}

func TestGenerateEd25519KeyPair(t *testing.T) {
	keyPair, err := keystore.GenerateEd25519KeyPair("adfadfaf")
	require.NoError(t, err)

	fmt.Println(keyPair.PublicKey)
	fmt.Println(keyPair.PrivateKey)
}

func TestTransferWithAction(t *testing.T) {
	a := buildAccount()
	receiveAccountID := "example-account344.testdafa.testnet"
	finalExecutionOutcome, transactionErr := a.SendMoney(receiveAccountID, *big.NewInt(10))
	require.NoError(t, transactionErr, "报错了")
	fmt.Println(finalExecutionOutcome)
}
