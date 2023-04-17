/*
 * @Author: huyongchao huyongchao98@163.com
 * @Date: 2023-04-08 14:16:20
 * @LastEditors: 胡勇超 huyongchao98@163.com
 * @LastEditTime: 2023-04-17 18:42:30
 * @FilePath: /near-api-go/account_test.go
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
package near

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"testing"

	"github.com/aurora-is-near/near-api-go/keystore"
	"github.com/aurora-is-near/near-api-go/utils"
	"github.com/btcsuite/btcutil/base58"
	"github.com/near/borsh-go"
	"github.com/stretchr/testify/require"
)

func TestCreateAccountTransactionWithFunctionCall(t *testing.T) {

	newAccountID := "dfjadfjfdaf123234.testdafa.testnet"

	a := BuildAccount()

	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "报错了")

	pubKey := utils.PublicKeyFromEd25519(pub)

	pubKeyStr := base58.Encode(pubKey.Data[:])

	fmt.Println("pubKeyStr:", pubKeyStr)

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
	a := BuildAccount()
	receiveAccountID := "wrerr1wesdsdadad.testdafa.testnet"
	finalExecutionOutcome, transactionErr := a.SendMoney(receiveAccountID, *big.NewInt(150000000000000000))
	require.NoError(t, transactionErr, "报错了")
	fmt.Println(finalExecutionOutcome)
}

func TestBuildTrasaction(t *testing.T) {
	receiverID := "dfjadfjfdaf1232.testdafa.testnet"

	a := BuildAccount()

	bigIntAmount := big.NewInt(1000)

	actions := []Action{
		{
			Enum: 3,
			Transfer: Transfer{
				Deposit: *bigIntAmount,
			},
		},
	}

	transaction, buildTransactionErr := a.BuildTransaction(receiverID, actions)
	require.NoError(t, buildTransactionErr)

	txHash, signedTx, signTransactionObjectErr := signTransactionObject(transaction, a.kp.Ed25519PrivKey, a.kp.AccountID)

	require.NoError(t, signTransactionObjectErr)
	require.NotNil(t, txHash)

	buf, SerializeErr := borsh.Serialize(*signedTx)
	require.NoError(t, SerializeErr)

	resultMap, sentErr := a.conn.SendTransaction(buf)

	require.NoError(t, sentErr)

	require.NotNil(t, resultMap)

}
